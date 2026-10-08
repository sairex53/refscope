#!/usr/bin/env python3
"""Root-only live capture checks. Each output directory is new; no kernel settings changed."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time

p=argparse.ArgumentParser()
p.add_argument('--runs',type=int,default=100)
p.add_argument('--cycles',type=int,default=1)
p.add_argument('--threads',type=int,default=1,help='>1 uses concurrent fixture on distinct CPUs')
p.add_argument('--backend',choices=['auto','kprobe','fentry'],default='auto')
p.add_argument('--ring-size',type=int,default=16777216)
p.add_argument('--allow-drops',action='store_true')
p.add_argument('--require-drops',action='store_true')
p.add_argument('--output',type=Path,required=True)
p.add_argument('--self-filters',action='store_true')
p.add_argument('--expect-empty',action='store_true')
p.add_argument('--no-stacks',action='store_true')
a=p.parse_args()
assert os.geteuid()==0 and a.runs>0 and 0<a.cycles<=1000000
cpus=sorted(os.sched_getaffinity(0))
assert 1<=a.threads<=len(cpus)
a.output.mkdir(parents=True,exist_ok=False)
expected=[('CREATE',0),('GET',1),('GET',2),('PUT',2),('PUT',1),('FREE',0)]
cmd=['./build/refscope','trace','--duration','300s','--format','jsonl','--backend',a.backend,'--ring-size',str(a.ring_size)]
kinds=['GET','PUT'] if a.threads>1 else ['CREATE','GET','PUT','FREE']
for kind in kinds: cmd+=['--'+kind.lower(),'rs_test_'+kind.lower()+':obj=arg0,reason=arg1']
if a.self_filters:
    assert a.threads==1
    os.sched_setaffinity(0,{cpus[0]})
    cmd+=['--pid',str(os.getpid()),'--tid',str(os.getpid()),'--comm',Path('/proc/self/comm').read_text().strip(),'--cpu',str(cpus[0])]
if a.expect_empty: cmd+=['--object','0x1']
if a.no_stacks: cmd+=['--no-stacks']
def trigger():
    tids=set(); errors=[]; intervals=[]
    barrier=threading.Barrier(a.threads)
    def write(index):
        try:
            if a.threads>1: os.sched_setaffinity(0,{cpus[index]})
            tids.add(threading.get_native_id())
            barrier.wait(timeout=10)
            begin=time.monotonic_ns()
            Path('/sys/kernel/debug/refscope_test/'+('concurrent' if a.threads>1 else 'run')).write_text(str(a.cycles))
            intervals.append((begin,time.monotonic_ns()))
        except BaseException as e:
            errors.append(e); barrier.abort()
    start=time.monotonic(); cpu=time.process_time()
    if a.threads==1: write(0)
    else:
        workers=[threading.Thread(target=write,args=(i,)) for i in range(a.threads)]
        for t in workers: t.start()
        for t in workers: t.join(120)
        assert not any(t.is_alive() for t in workers),'workload timeout'
    assert not errors,errors
    overlap=min(t[1] for t in intervals)-max(t[0] for t in intervals)
    return time.monotonic()-start,time.process_time()-cpu,tids,overlap
symbol='concurrent_object' if a.threads>1 else 'object'
objects=[line.split()[0] for line in Path('/proc/kallsyms').read_text().splitlines() if line.split()[2:]==[symbol,'[refscope_test]']]
assert len(objects)==1 and int(objects[0],16)
expected_object=int(objects[0],16)
baseline,baseline_cpu,_,_=trigger()
results=[]
for run in range(a.runs):
    path=a.output/f'{run:03d}.jsonl'; log=a.output/f'{run:03d}.stderr'
    with path.open('w') as out,log.open('w') as errlog:
        start=time.monotonic()
        proc=subprocess.Popen(cmd,stdout=out,stderr=errlog)
        try:
            deadline=time.monotonic()+30
            while '\nready\n' not in '\n'+log.read_text():
                assert proc.poll() is None,log.read_text()
                assert time.monotonic()<deadline,'ready timeout: '+log.read_text()
                time.sleep(.01)
            ready=time.monotonic(); earliest=time.monotonic_ns()
            elapsed,producer_cpu,tids,overlap=trigger()
            latest=time.monotonic_ns()
            proc.send_signal(signal.SIGINT)
            deadline=time.monotonic()+60
            while True:
                pid,status,usage=os.wait4(proc.pid,os.WNOHANG)
                if pid: break
                assert time.monotonic()<deadline,'drain timeout'
                time.sleep(.01)
            proc.returncode=os.waitstatus_to_exitcode(status)
            drained=time.monotonic()-ready
            total=time.monotonic()-start
            assert proc.returncode==0,log.read_text()
        finally:
            if proc.returncode is None: proc.kill(); proc.wait()
    count=0; stacks={}; used_stacks=set(); last={}; seen_objects=set(); summary=None; worker_events={}
    with path.open() as stream:
        for line in stream:
            r=json.loads(line); assert r['schema_version']==1
            if r['record']=='stack':
                assert r['frames'] and r['stack_id'] not in stacks
                assert any(f['symbol']!='unknown' for f in r['frames'])
                stacks[r['stack_id']]=r
            elif r['record']=='event':
                assert summary is None
                if a.no_stacks: assert r['stack_id']==-1
                else: assert r['stack_id']>=0; used_stacks.add(r['stack_id'])
                assert int(r['object'],16)==expected_object
                assert earliest<=r['ts_ns']<=latest and r['pid']==os.getpid() and r['tid'] in tids
                previous=last.get(r['cpu'],(0,0))
                assert r['sequence']>previous[0] and r['ts_ns']>=previous[1]
                if not a.allow_drops: assert r['sequence']==previous[0]+1
                last[r['cpu']]=(r['sequence'],r['ts_ns'])
                n=worker_events.get(r['tid'],0)
                if not a.allow_drops:
                    if a.threads==1: assert (r['type'],r['reason'])==expected[count%6]
                    else:
                        assert r['type']==('GET' if n%2==0 else 'PUT')
                        assert r['reason']==(r['tid']<<32)|(n//2)
                worker_events[r['tid']]=n+1
                seen_objects.add(r['object']);count+=1
            elif r['record']=='summary': assert summary is None; summary=r
            else: raise AssertionError(r)
    assert used_stacks<=stacks.keys()
    assert summary and summary['transport_complete'] and summary['loss_counters_known']
    assert summary['captured']==count
    expected_count=(2*a.threads if a.threads>1 else 6)*a.cycles
    assert summary['attempted']==(0 if a.expect_empty else expected_count)
    assert summary['captured']+summary['dropped']==summary['attempted']
    assert summary['dropped']==summary['ring_dropped']+summary['nested_dropped']
    assert summary['stack_errors']==summary['userspace_stack_lookup_errors']==summary['ordering_errors']==0
    assert summary['kernel_recursion_misses']==summary['kprobe_misses']==0,summary
    assert len(seen_objects)==(0 if a.expect_empty else 1)
    if not a.allow_drops: assert summary['dropped']==0 and not summary['incomplete']
    if summary['dropped']: assert summary['incomplete']
    if a.require_drops: assert summary['dropped']>0
    if a.threads>1:
        assert len(last)>=2 and len(worker_events)==a.threads and overlap>0
        if not a.allow_drops: assert all(n==2*a.cycles for n in worker_events.values())
    result=dict(run=run,threads=a.threads,cpus_observed=len(last),baseline_seconds=baseline,baseline_producer_cpu_seconds=baseline_cpu,
        workload_seconds=elapsed,producer_cpu_seconds=producer_cpu,concurrent_overlap_ns=overlap,capture_and_drain_seconds=drained,
        total_process_seconds=total,tracer_cpu_seconds=usage.ru_utime+usage.ru_stime,tracer_peak_rss_kib=usage.ru_maxrss,
        delivered_events_per_second=count/drained,**summary)
    results.append(result)
    (a.output/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    if (run+1)%10==0: print(f'{run+1}/{a.runs} passed',flush=True)
print(json.dumps(dict(runs=a.runs,cycles=a.cycles,last=results[-1])))
