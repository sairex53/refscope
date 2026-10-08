#!/usr/bin/env python3
"""Focused auto-backend attach fallback and cleanup integration checks."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess as sp
import time

p = argparse.ArgumentParser()
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
assert os.geteuid() == 0
a.output.mkdir(parents=True, exist_ok=False)

ROOT = Path.cwd()
DEBUGFS = Path('/sys/kernel/debug/refscope_test')
FAULTS = ROOT / 'build/faults.so'
cmd = [str(ROOT / 'build/refscope'), 'trace', '--get',
       'rs_test_get:obj=arg0,reason=arg1', '--put',
       'rs_test_put:obj=arg0,reason=arg1', '--format', 'jsonl',
       '--backend', 'auto', '--duration', '300s']
libbpf = ctypes.CDLL('libbpf.so.1', use_errno=True)


def resources():
    result = {}
    for kind in ('prog', 'map', 'link'):
        ids = set()
        current = ctypes.c_uint(0)
        following = ctypes.c_uint()
        fn = getattr(libbpf, 'bpf_' + kind + '_get_next_id')
        while fn(current, ctypes.byref(following)) == 0:
            ids.add(following.value)
            current.value = following.value
        assert ctypes.get_errno() == 2
        result[kind] = ids
    return result


def clean(base):
    deadline = time.monotonic() + 5
    while True:
        after = resources()
        if all(after[k] <= base[k] for k in base):
            return after
        if time.monotonic() >= deadline:
            raise AssertionError((base, after))
        time.sleep(.05)


def map_snapshot(pid):
    maps = {}
    for fdinfo in Path('/proc', str(pid), 'fdinfo').glob('*'):
        try:
            text = fdinfo.read_text()
        except OSError:
            continue
        fields = {}
        for line in text.splitlines():
            key, _, value = line.partition(':')
            if key in ('map_id', 'map_name'):
                fields[key] = value.strip()
        if 'map_id' in fields:
            maps.setdefault(fields.get('map_name', '<unnamed>'), set()).add(int(fields['map_id']))
    return maps


def wait_ready(proc, log):
    deadline = time.monotonic() + 30
    while '\nready\n' not in '\n' + log.read_text():
        assert proc.poll() is None, log.read_text()
        assert time.monotonic() < deadline, 'ready timeout: ' + log.read_text()
        time.sleep(.01)


def run_success(name, fault, base):
    env = dict(os.environ, LD_PRELOAD=str(FAULTS), RS_TEST_FAULT=fault)
    out = a.output / (name + '.jsonl')
    log = a.output / (name + '.stderr')
    with out.open('w') as stream, log.open('w') as errors:
        proc = sp.Popen(cmd, stdout=stream, stderr=errors, env=env)
        try:
            wait_ready(proc, log)
            maps = map_snapshot(proc.pid)
            map_ids = set().union(*maps.values()) if maps else set()
            # The skeleton has events, stats, stacks, .rodata and .bss maps.
            # Both target skeletons must share these five IDs; ten would prove
            # that fallback accidentally created a second map set.
            assert len(map_ids) == 5, maps
            DEBUGFS.joinpath('run').write_text('1')
            proc.send_signal(signal.SIGINT)
            rc = proc.wait(timeout=60)
            assert rc == 0, log.read_text()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    events = [row for row in rows if row['record'] == 'event']
    summary = [row for row in rows if row['record'] == 'summary']
    assert len(events) == 4, events
    assert [
        (row['target_id'], row['type'], row['reason']) for row in events
    ] == [(0, 'GET', 1), (0, 'GET', 2), (1, 'PUT', 2), (1, 'PUT', 1)], events
    assert {row['target_id'] for row in events} == {0, 1}
    assert len(summary) == 1
    summary = summary[0]
    assert summary['captured'] == 4 and summary['attempted'] == 4
    assert summary['dropped'] == 0 and summary['stack_errors'] == 0
    assert summary['userspace_stack_lookup_errors'] == 0
    assert summary['ordering_errors'] == 0 and not summary['incomplete']
    assert summary['backend'] == 'mixed', summary
    clean(base)
    return maps, summary


def run_failure(name, fault, base):
    env = dict(os.environ, LD_PRELOAD=str(FAULTS), RS_TEST_FAULT=fault)
    out = a.output / (name + '.jsonl')
    log = a.output / (name + '.stderr')
    with out.open('w') as stream, log.open('w') as errors:
        proc = sp.Popen(cmd, stdout=stream, stderr=errors, env=env)
        try:
            rc = proc.wait(timeout=60)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
    text = log.read_text()
    assert rc != 0
    assert 'attach rejected for rs_test_put: Operation not permitted; releasing all previously attached targets' in text
    assert 'fentry attach unavailable for rs_test_put (Operation not permitted); falling back to kprobe' in text
    assert 'capture failed: Operation not permitted' in text
    assert not out.read_text().strip()
    clean(base)


assert FAULTS.exists()
assert DEBUGFS.joinpath('run').exists()
base = resources()
run_success('fentry-first', 'fentry-attach-first', base)
run_success('fentry-second', 'fentry-attach-second', base)
run_failure('fentry-second-kprobe', 'fentry-second-kprobe', base)
print('fallback scenarios PASS: first target, second target, double attach failure; resources cleaned')
