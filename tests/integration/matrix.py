#!/usr/bin/env python3
"""Final v0.0.1 matrix. Requires an already-loaded matching synthetic module."""
import argparse,hashlib,json,os,platform,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
assert os.geteuid()==0 and Path('/sys/module/refscope_test').exists()
a.output.mkdir(parents=True,exist_ok=False)
files=[Path('Makefile'),*Path('src').rglob('*.c'),*Path('bpf').rglob('*.c'),*Path('include').rglob('*.h'),*Path('tests').rglob('*.py'),*Path('tests').rglob('*.c')]
meta=dict(kernel=platform.release(),architecture=platform.machine(),started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),sha256={str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in files if not f.name.endswith('.mod.c')})
(a.output/'metadata.json').write_text(json.dumps(meta,indent=2)+'\n')
subprocess.run(['make','build/faults.so'],check=True)
steps=[]
for backend in ['fentry','kprobe']:
    steps.append((backend+'-100',['--runs','100','--backend',backend]))
    steps.append((backend+'-concurrent',['--runs','1','--threads','4','--cycles','25000','--backend',backend,'--ring-size','268435456']))
    steps.append((backend+'-stress',['--runs','1','--cycles','250000','--backend',backend,'--ring-size','268435456']))
steps += [('overload-16m',['--runs','1','--cycles','250000','--backend','kprobe','--allow-drops','--require-drops']),('filters',['--runs','1','--self-filters']),('no-stacks',['--runs','1','--no-stacks']),('excluded',['--runs','1','--expect-empty'])]
steps += [('fallback',None)]
results=[]
for name,args in steps+[('lifecycle',None)]:
    if name == 'fallback':
        command=['python3','tests/integration/fallback.py','--output',str(a.output/name)]
    else:
        command=['python3','tests/integration/'+('lifecycle.py' if args is None else 'capture.py'),*(args or []),'--output',str(a.output/name)]
    print('BEGIN',name,flush=True);start=time.monotonic()
    with (a.output/(name+'.log')).open('w') as log:
        proc=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        for line in proc.stdout:
            log.write(line);log.flush();print(line.rstrip(),flush=True)
        code=proc.wait()
    results.append(dict(name=name,exit_code=code,seconds=time.monotonic()-start))
    (a.output/'matrix.json').write_text(json.dumps(results,indent=2)+'\n')
    if code: raise SystemExit(code)
    print('PASS',name,flush=True)
print('ALL MATRIX STEPS PASSED',flush=True)
