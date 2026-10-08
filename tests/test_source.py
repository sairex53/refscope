"""Exercise libdw with controlled ELF fixtures, never fake a real kernel result."""
from pathlib import Path
import subprocess as sp
import shlex
import os
out=Path('build/source-tests'); out.mkdir(parents=True, exist_ok=True)
fixture=out/'fixture.c'
fixture.write_text('__attribute__((noinline)) int _stext(int x) { return x + 7; }\n__attribute__((noinline)) int _etext(int x) { return x; }\nint main(void) { return _etext(_stext(0)); }\n')
sp.run(['cc','-g','-O0','-fno-toplevel-reorder','-no-pie',str(fixture),'-o',str(out/'fixture')],check=True)
sp.run(['objcopy','--dump-section',f'.note.gnu.build-id={out}/notes',str(out/'fixture')],check=True)
sp.run(['objcopy','--strip-debug',str(out/'fixture'),str(out/'stripped')],check=True)
(out/'bad-notes').write_bytes(b'not ELF notes')
(out/'corrupt').write_bytes(b'not ELF')
harness=out/'check.c'
harness.write_text('''#include "refscope/source.h"
#include <stdio.h>
#include <stdlib.h>
int main(int argc,char **argv) {
 if(argc!=5) return 2;
 const char *status=rs_source_open(argv[1],argv[2],0x10000000);
 puts(status);
 const char *file=NULL; int line=0;
 int found=rs_source_lookup(strtoull(argv[3],NULL,0),&file,&line);
 if(found) printf("%s:%d\\n",file,line);
 rs_source_close();
 return found != atoi(argv[4]);
}
''')
def build(name,flags):
    sp.run(['cc','-Wall','-Wextra','-Werror','-Iinclude',str(harness),'src/symbols/source.c','-o',str(out/name),*flags],check=True)
def run(binary,elf,notes,addr,yes):
    p=sp.run([str(out/binary),str(out/elf),str(out/notes),addr,str(yes)],capture_output=True,text=True)
    assert p.returncode==0,(p.stdout,p.stderr,elf)
    if yes: assert 'fixture.c:1' in p.stdout,p.stdout
build('no-dwarf',[])
run('no-dwarf','fixture','notes','0x10000000',0)
if sp.run(['pkg-config','--exists','libdw']).returncode==0:
    flags=shlex.split(sp.check_output(['pkg-config','--cflags','--libs','libdw'],text=True))
    build('check',['-DRS_HAVE_LIBDW',*flags])
    for elf,notes,addr,yes in [('fixture','notes','0x10000000',1),('fixture','bad-notes','0x10000000',0),('stripped','notes','0x10000000',0),('missing','notes','0x10000000',0),('corrupt','notes','0x10000000',0),('fixture','notes','0xffff000000000000',0),('fixture','notes','0xfffffff',0)]:
        run('check',elf,notes,addr,yes)
    print('DWARF fixtures: matching, mismatch, stripped, missing, corrupt, relocated bounds PASS')
print('No-DWARF build/fallback: PASS')
