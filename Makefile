CC ?= cc
CLANG ?= clang
BPFTOOL ?= bpftool
HOST_ARCH ?= $(shell uname -m)
ifeq ($(HOST_ARCH),aarch64)
BPF_ARCH := arm64
else ifeq ($(HOST_ARCH),x86_64)
BPF_ARCH := x86
else
BPF_ARCH :=
endif
CFLAGS ?= -O2 -g
CPPFLAGS += -Iinclude -Ibuild
WITH_DWARF ?= $(shell pkg-config --exists libdw && echo 1 || echo 0)
ifeq ($(WITH_DWARF),1)
CPPFLAGS += -DRS_HAVE_LIBDW $(shell pkg-config --cflags libdw)
DWARF_LIBS := $(shell pkg-config --libs libdw)
endif
WARN := -Wall -Wextra -Werror
.PHONY: all clean test module module-btf faults FORCE
all: build/refscope
build:
	mkdir -p $@
build/vmlinux.h: | build
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp
	mv $@.tmp $@
build/trace.bpf.o: bpf/trace.bpf.c include/refscope/event.h build/vmlinux.h
	@if [ -z "$(BPF_ARCH)" ]; then \
		echo "error: unsupported host architecture '$(HOST_ARCH)'; RefScope v0.0.1 currently supports aarch64 and x86_64" >&2; \
		exit 2; \
	fi
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH) $(CPPFLAGS) -c $< -o $@
build/trace.skel.h: build/trace.bpf.o
	$(BPFTOOL) gen skeleton $< > $@.tmp
	mv $@.tmp $@
build/refscope: src/cli/main.c src/capture/target.c src/symbols/source.c src/provenance/inspector.py src/provenance/target_adapter.py include/refscope/source.h include/refscope/target.h build/trace.skel.h
	$(CC) $(CFLAGS) $(WARN) $(CPPFLAGS) src/cli/main.c src/capture/target.c src/symbols/source.c -o $@ $(DWARF_LIBS) $$(pkg-config --cflags --libs libbpf libelf)
build/faults.so: tests/integration/faults.c | build
	$(CC) -shared -fPIC $(CPPFLAGS) $< -o $@ $$(pkg-config --cflags --libs libbpf) -ldl
faults: build/faults.so
build/test-target: tests/test_target.c src/capture/target.c include/refscope/target.h | build
	$(CC) $(CFLAGS) $(WARN) $(CPPFLAGS) tests/test_target.c src/capture/target.c -o $@
build/test-json: tests/test_json.c src/cli/main.c src/capture/target.c src/symbols/source.c include/refscope/source.h include/refscope/target.h build/trace.skel.h
	$(CC) $(CFLAGS) $(WARN) $(CPPFLAGS) tests/test_json.c src/capture/target.c src/symbols/source.c -o $@ $(DWARF_LIBS) $$(pkg-config --cflags --libs libbpf libelf)
test: build/test-target build/test-json build/refscope
	./build/test-target
	python3 tests/test_json.py
	python3 tests/test_cli.py
	python3 tests/test_source.py
	python3 tests/test_timeline.py
	python3 tests/test_timeline_cli.py
	python3 tests/test_timeline_bundle.py
	python3 tests/test_diagnosis_input.py
	python3 tests/test_provenance.py
	python3 tests/test_provenance_adapters.py
	python3 tests/test_target_inspector.py
	python3 tests/test_diagnosis_alignment.py
	python3 tests/test_diagnosis_rules.py
	python3 tests/test_diagnosis_cli.py
	python3 tests/test_diagnosis_synthetic_accuracy.py
	python3 tests/test_syzbot_intake.py
module:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(CURDIR)/tests/synthetic modules
clean:
	rm -rf build

# Optional split BTF for fentry tests when distro kernel-devel lacks vmlinux.
module-btf: module
	pahole -J --btf_base /sys/kernel/btf/vmlinux tests/synthetic/refscope_test.ko

FORCE:
build/config: FORCE | build
	@printf "%s\n" "$(WITH_DWARF) $(HOST_ARCH) $(CFLAGS)" > $@.tmp
	@cmp -s $@.tmp $@ || cp $@.tmp $@
build/refscope build/test-json build/trace.bpf.o: build/config
