#!/usr/bin/env python3
import argparse, ctypes, json, os, signal, subprocess as sp, time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=False)
assert os.geteuid()==0
cmd=['./build/refscope','trace','--get','rs_test_get:obj=arg0,reason=arg1','--put','rs_test_put:obj=arg0,reason=arg1','--format','jsonl','--backend','fentry','--duration','.1s']
libbpf=ctypes.CDLL('libbpf.so.1',use_errno=True)
def resources():
    result={}
    for kind in ['prog','map','link']:
        ids=set(); current=ctypes.c_uint(0); following=ctypes.c_uint()
        fn=getattr(libbpf,'bpf_'+kind+'_get_next_id')
        while fn(current,ctypes.byref(following))==0:
            ids.add(following.value);current.value=following.value
        assert ctypes.get_errno()==2
        result[kind]=ids
    return result
base=resources()
def clean():
    deadline=time.monotonic()+5
    while True:
        after=resources()
        if all(after[k]<=base[k] for k in base): return
        if time.monotonic()>=deadline: break
        time.sleep(.05)
    assert all(after[k]<=base[k] for k in base),(base,after)
def run(name,args,expected,env=None,trigger=False,sig=None,broken=False):
    log=a.output/(name+'.stderr');out=a.output/(name+'.jsonl')
    with log.open('w') as err,out.open('w') as dst:
        proc=sp.Popen(args,stderr=err,stdout=sp.PIPE if broken else dst,env=env)
        try:
            if broken: proc.stdout.close()
            if trigger or sig:
                deadline=time.monotonic()+20
                while '\nready\n' not in '\n'+log.read_text():
                    assert proc.poll() is None,log.read_text()
                    assert time.monotonic()<deadline
                    time.sleep(.01)
                if trigger: Path('/sys/kernel/debug/refscope_test/run').write_text('1')
                if sig: proc.send_signal(sig)
            rc=proc.wait(timeout=30)
            assert rc==expected,(name,rc,log.read_text())
        finally:
            if proc.poll() is None: proc.kill();proc.wait()
    clean()
    rows=[json.loads(l) for l in out.read_text().splitlines()]
    print(name,'PASS',flush=True)
    return rows
run('timeout',cmd,0)
for name,sig in [('sigint',signal.SIGINT),('sigterm',signal.SIGTERM)]:
    rows=run(name,cmd[:-1]+['10s'],0,trigger=True,sig=sig)
    assert rows[-1]['captured']==4 and not rows[-1]['incomplete']
run('broken-output',cmd,1,broken=True)
for mode in ['partial-attach','ring-new','poll-error','poll-eintr','consume-error','stats-read','stack-read','reuse','load','link-info']:
    env=dict(os.environ,LD_PRELOAD=str(Path('build/faults.so').resolve()),RS_TEST_FAULT=mode)
    mode_cmd=cmd.copy()
    if mode=='link-info': mode_cmd[mode_cmd.index('--backend')+1]='kprobe'
    rows=run(mode,mode_cmd,0 if mode in ['poll-eintr','stack-read','link-info'] else 1,env,trigger=mode=='stack-read')
    if mode=='stats-read': assert rows[-1]['attempted'] is None and rows[-1]['incomplete']
    if mode=='stack-read': assert rows[-1]['captured']==4 and rows[-1]['userspace_stack_lookup_errors']>0 and rows[-1]['incomplete']
    if mode=='partial-attach': assert 'releasing all previously attached' in (a.output/(mode+'.stderr')).read_text()
    if mode=='link-info': assert rows[-1]['kprobe_misses'] is None and rows[-1]['incomplete'] and isinstance(rows[-1]['kernel_miss_snapshot'], bool)
for name,args,rc in [('dry-run',cmd+['--dry-run'],0),('bad-arg',['./build/refscope','trace','--get','rs_test_get:obj=arg1','--dry-run'],2),('absent',['./build/refscope','trace','--get','rs_nonexistent:obj=arg0','--dry-run'],2)]:
    run(name,args,rc)
run('no-btf',cmd,2,dict(os.environ,LD_PRELOAD=str(Path('build/faults.so').resolve()),RS_TEST_FAULT='no-btf'))
print('lifecycle/fault matrix PASS; no new BPF programs/maps/links remain')
