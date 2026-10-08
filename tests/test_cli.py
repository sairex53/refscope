import subprocess
cases = [[], ['--get','x:obj=arg5'], ['--duration','nan'], ['--duration','inf'], ['--duration','0s'], ['--duration','1ms'], ['--pid','-1'], ['--pid','0'], ['--comm','x'*16], ['--cpu','1,,2'], ['--cpu','3-1'], ['--cpu','4096'], ['--format','yaml'], ['--backend','fake'], ['--ring-size','3'], ['--get','f:obj=arg0','--put','f:obj=arg0']]
for case in cases:
    p = subprocess.run(['./build/refscope','trace',*case], capture_output=True)
    assert p.returncode == 2, (case, p.returncode, p.stderr)
assert subprocess.run(['./build/refscope','--help'],capture_output=True).returncode == 0
print('CLI rejection tests: passed')
