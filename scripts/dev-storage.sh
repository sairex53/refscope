#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
DATA_ROOT="${REFSCOPE_DATA_ROOT:-$HOME/refscope-data}"
PROJECTS_ROOT="$HOME/projects"
ACTION="${1:-inventory}"
APPLY=0

if [[ "$ACTION" == "clean-rebuildables" ]]; then
    if [[ "${2:-}" == "--apply" ]]; then
        APPLY=1
    elif [[ $# -gt 1 ]]; then
        printf 'Usage: %s [inventory | clean-rebuildables [--apply]]\n' "$0" >&2
        exit 2
    fi
elif [[ "$ACTION" != "inventory" || $# -gt 1 ]]; then
    printf 'Usage: %s [inventory | clean-rebuildables [--apply]]\n' "$0" >&2
    exit 2
fi

size_of() {
    local path="$1"
    local du_status=0
    local du_output
    local measured_size
    local diagnostics
    if [[ ! -e "$path" && ! -L "$path" ]]; then
        printf 'ABSENT'
        return
    fi
    du_output="$(du -shx -- "$path" 2>&1)" || du_status=$?
    measured_size="$(printf '%s\n' "$du_output" | awk '$1 ~ /^[0-9]+([.][0-9]+)?[KMGTPE]?$/ { value=$1 } END { print value }')"
    if [[ -z "$measured_size" ]]; then
        printf 'WARNING: no size could be measured for %s; inspect: %s\n' "$path" "$du_output" >&2
        printf 'UNAVAILABLE'
        return
    fi
    if [[ "$du_status" -ne 0 ]]; then
        diagnostics="$(printf '%s\n' "$du_output" | awk '/^du:/ { if (count++) printf "; "; printf "%s", $0 }')"
        printf 'WARNING: partial size for %s (du exit %s): %s\n' "$path" "$du_status" "$diagnostics" >&2
        printf '%s*' "$measured_size"
    else
        printf '%s' "$measured_size"
    fi
}

row() {
    local classification="$1"
    local path="$2"
    local note="$3"
    printf '%-16s %-12s %-68s %s\n' "$classification" "$(size_of "$path")" "$path" "$note"
}

python_cache_paths() {
    find "$ROOT/src" "$ROOT/tests" -xdev -type d -name __pycache__ -prune -print0 2>/dev/null
}

inventory() {
    printf 'RefScope storage inventory (read-only)\n'
    printf 'Project root: %s\n' "$ROOT"
    printf 'Data root:    %s\n' "$DATA_ROOT"
    printf 'Disk:         '
    df -h --output=source,size,used,avail,pcent "$ROOT" | tail -n 1
    printf 'Directory sizes overlap; do not add parent and child rows.\n\n'
    printf '%-16s %-12s %-68s %s\n' CLASS SIZE PATH NOTE
    row PERMANENT "$ROOT" 'source tree and complete project total; retain'
    row PERMANENT "$ROOT/.git" 'history and repository metadata; retain'
    row REBUILDABLE "$ROOT/build" 'Makefile-generated outputs; sole build cleanup target'
    row PERMANENT "$ROOT/cases" 'reviewed case inputs and research records; retain'
    row PERMANENT "$ROOT/docs" 'design and roadmap; retain'
    row PERMANENT "$ROOT/src" 'tracked source; never cleaned'
    row PERMANENT "$ROOT/tests" 'tests and fixtures; never cleaned'
    while IFS= read -r -d '' cache; do
        row REBUILDABLE "$cache" 'Python bytecode cache only'
    done < <(python_cache_paths)

    if [[ -d "$DATA_ROOT" ]]; then
        printf '\nData-root inventory (only known retained data is classified permanent):\n'
        shopt -s nullglob dotglob
        for entry in "$DATA_ROOT"/*; do
            [[ -e "$entry" || -L "$entry" ]] || continue
            base="$(basename -- "$entry")"
            case "$base" in
                runs|backups|codex-progress.md|README.MD)
                    row PERMANENT "$entry" 'retained evidence, recovery copy, or progress record; never auto-clean'
                    ;;
                *)
                    row UNKNOWN "$entry" 'ownership or lifecycle is not verified; preserve'
                    ;;
            esac
        done
        if [[ -d "$DATA_ROOT/runs" ]]; then
            for entry in "$DATA_ROOT/runs"/*; do
                [[ -e "$entry" || -L "$entry" ]] || continue
                row PERMANENT "$entry" 'run evidence; inspect individually before any deletion'
            done
        fi
    else
        printf '\nData root is absent; no files created there by this inventory.\n'
    fi

    printf '\nKnown sibling projects (reported, never cleanup candidates):\n'
    row EXTERNAL/SHARED "$PROJECTS_ROOT/refscope-fedora-migrated-20261008" 'separate preserved project copy'
    row EXTERNAL/SHARED "$PROJECTS_ROOT/refscope-fedora-validation-20261008" 'separate preserved project copy'
    row UNKNOWN "$HOME/.cache" 'user-wide cache can be shared by other work; do not clean blindly'

    printf '\nInstalled shared build dependencies (RPM installed size in bytes; do not remove here):\n'
    if command -v rpm >/dev/null 2>&1; then
        rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE} %{SIZE}\n' \
            gcc clang make bpftool libbpf-devel elfutils-libelf-devel \
            elfutils-devel pkgconf-pkg-config python3 2>&1 || true
    else
        printf 'rpm unavailable; package inventory not collected\n'
    fi
    if command -v pkg-config >/dev/null 2>&1; then
        printf 'pkg-config libbpf/libelf/libdw: '
        pkg-config --modversion libbpf libelf libdw 2>&1 || true
    fi

    printf '\nShared container inventory (read-only; no stop/prune/remove operations):\n'
    if command -v podman >/dev/null 2>&1; then
        podman ps --all --size 2>&1 || true
        podman system df 2>&1 || true
    else
        printf 'podman unavailable\n'
    fi

    printf '\nCleanup whitelist: this repository build/ and src/tests Python __pycache__ only.\n'
    printf 'No packages, containers, sibling projects, case inputs, evidence, backups, or unknown data are eligible.\n'
}

active_refscope_work() {
    ps -eo pid=,args= | awk -v root="$ROOT" -v self="$$" '
        $1 == self || /awk/ || /dev-storage\.sh/ { next }
        index($0, root "/build/refscope") ||
        index($0, root "/tests/integration/capture.py") ||
        index($0, root "/tests/integration/matrix.py") ||
        index($0, root "/tests/integration/lifecycle.py") ||
        $0 ~ /tests\/integration\/(capture|matrix|lifecycle)\.py/ ||
        $0 ~ /(^|[[:space:]])make([[:space:]].*)[[:space:]](test|all)([[:space:]]|$)/ {
            print
        }
    '
}

validate_build_target() {
    local resolved
    local expected
    local recipe
    if [[ ! -e "$ROOT/.git" || ! -f "$ROOT/Makefile" ]]; then
        printf 'Refusing cleanup: project root or Makefile is missing.\n' >&2
        return 1
    fi
    if [[ -L "$ROOT/build" ]]; then
        printf 'Refusing cleanup: build/ is a symlink.\n' >&2
        return 1
    fi
    if [[ -e "$ROOT/build" ]]; then
        resolved="$(realpath -e -- "$ROOT/build")" || return 1
        expected="$ROOT/build"
        if [[ "$resolved" != "$expected" || ! -d "$resolved" ]]; then
            printf 'Refusing cleanup: resolved build path is not the exact project build directory.\n' >&2
            return 1
        fi
    fi
    recipe="$(make --no-print-directory -n -C "$ROOT" clean 2>/dev/null)" || {
        printf 'Refusing cleanup: cannot inspect the Makefile clean recipe.\n' >&2
        return 1
    }
    if [[ "$recipe" != "rm -rf build" ]]; then
        printf 'Refusing cleanup: Makefile clean recipe changed; expected only rm -rf build.\n' >&2
        printf 'Observed recipe: %s\n' "$recipe" >&2
        return 1
    fi
}

clean_rebuildables() {
    local active
    local cache
    local confirmation
    printf 'Cleanup preview (no files will be removed):\n'
    row REBUILDABLE "$ROOT/build" 'generated build tree; make clean recipe is checked before use'
    while IFS= read -r -d '' cache; do
        row REBUILDABLE "$cache" 'Python bytecode cache'
    done < <(python_cache_paths)
    printf 'The preview excludes source, Git data, case bundles, saved evidence, backups, packages, containers, and sibling projects.\n'

    if [[ "$APPLY" -ne 1 ]]; then
        printf 'DRY RUN: no changes made. Add --apply and confirm interactively to execute.\n'
        return 0
    fi
    if [[ ! -t 0 ]]; then
        printf 'Refusing cleanup: --apply requires an interactive terminal.\n' >&2
        return 4
    fi
    validate_build_target || return 4
    active="$(active_refscope_work)"
    if [[ -n "$active" ]]; then
        printf 'Refusing cleanup while RefScope or its capture tests are active:\n%s\n' "$active" >&2
        return 4
    fi
    printf 'Type exactly CLEAN REFSCOPE REBUILDABLES to continue: '
    IFS= read -r confirmation
    if [[ "$confirmation" != "CLEAN REFSCOPE REBUILDABLES" ]]; then
        printf 'Cancelled; no files changed.\n'
        return 3
    fi

    validate_build_target || return 4
    active="$(active_refscope_work)"
    if [[ -n "$active" ]]; then
        printf 'Refusing cleanup: matching work started after the preview:\n%s\n' "$active" >&2
        return 4
    fi

    if [[ -d "$ROOT/build" ]]; then
        make --no-print-directory -s -C "$ROOT" clean
    fi
    while IFS= read -r -d '' cache; do
        [[ -L "$cache" ]] && continue
        rm -rf -- "$cache"
    done < <(python_cache_paths)
    printf 'Removed only the confirmed rebuildable project outputs.\n'
}

case "$ACTION" in
    inventory) inventory ;;
    clean-rebuildables) clean_rebuildables ;;
esac
