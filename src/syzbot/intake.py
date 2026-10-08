"""Offline syzbot report intake and conservative kernel environment validation."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SCHEMA_VERSION = 1
ARTIFACT_NAMES = {
    "config": ".config",
    "syz_reproducer": "repro.syz",
    "c_reproducer": "repro.c",
    "original_log": "crash.log",
    "bisection": "bisection.txt",
    "target_yaml": "target.yaml",
}
KNOWN_FIELDS = {
    "schema_version", "bug_id", "title", "report_url", "url", "kernel_commit",
    "kernel_release", "architecture", "arch", "compiler", "config_provenance",
    "vmlinux_build_id", "kernel_build_id", "target_source_commit",
    "target_module_build_id", "target_module", "target_source_commit", "artifacts",
    "bisection_information", "bisection", "sanitizer_configuration", "report",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _clean_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip(".-_")
    return (cleaned or "unknown-case")[:100]


def _normalized_arch(value: str | None) -> str | None:
    if value is None:
        return None
    return {"amd64": "x86_64", "arm64": "aarch64"}.get(value.casefold(), value.casefold())


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"malformed report JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("report JSON root must be an object")
    return value


def _parse_text(text: str) -> dict[str, Any]:
    """Extract only explicit report headers; preserve the original text separately."""
    fields: dict[str, Any] = {}
    labels = {
        "title": "title", "kernel commit": "kernel_commit", "kernel release": "kernel_release",
        "kernel version": "kernel_release", "architecture": "architecture", "arch": "architecture",
        "compiler": "compiler", "report url": "report_url", "url": "report_url",
        "vmlinux build id": "vmlinux_build_id", "kernel build id": "kernel_build_id",
    }
    for line in text.splitlines():
        match = re.match(r"^\s*([A-Za-z][A-Za-z _-]*):\s*(.*?)\s*$", line)
        if match and match.group(1).casefold() in labels:
            key = labels[match.group(1).casefold()]
            if match.group(2):
                fields.setdefault(key, match.group(2))
    if not fields.get("title"):
        first = next((line.strip().lstrip("# ") for line in text.splitlines() if line.strip()), None)
        if first and len(first) <= 240 and not first.startswith(("BUG:", "WARNING:", "------------")):
            fields["title"] = first
    return fields


def _load_source(source: str) -> tuple[dict[str, Any], Path | None, str, str | None]:
    path = Path(source).expanduser()
    if path.exists():
        resolved = path.resolve()
        if resolved.is_dir():
            root = resolved
            metadata = next((candidate for base in (root, root / "input")
                             for name in ("report.json", "case.json", "metadata.json")
                             if (candidate := base / name).is_file()), None)
            text_path = next((candidate for base in (root, root / "input")
                              for name in ("report.txt", "crash.log", "syzbot.txt")
                              if (candidate := base / name).is_file()), None)
            if metadata:
                data = _read_json(metadata)
            elif text_path:
                data = _parse_text(text_path.read_text(encoding="utf-8", errors="replace"))
            else:
                raise ValueError("prepared directory needs report.json/case.json/metadata.json or report.txt")
            raw_report = metadata or text_path
            return data, root, str(resolved), str(raw_report) if raw_report else None
        if not resolved.is_file():
            raise ValueError("report source is not a regular file")
        if resolved.suffix.lower() == ".json":
            return _read_json(resolved), resolved.parent, str(resolved), str(resolved)
        try:
            text = resolved.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise ValueError(f"cannot read report: {exc}") from exc
        return _parse_text(text), resolved.parent, str(resolved), str(resolved)
    # A bug ID or URL is recorded as a locator only. No network lookup is performed.
    parsed = urlparse(source)
    if parsed.scheme in {"http", "https"}:
        return {"report_url": source}, None, source, None
    if re.fullmatch(r"[A-Za-z0-9._:-]+", source):
        return {"bug_id": source}, None, f"syzbot bug id: {source}", None
    raise ValueError(f"report source does not exist: {source}")


def _artifact_sources(data: dict[str, Any], root: Path | None) -> dict[str, Path]:
    supplied = data.get("artifacts", {})
    if supplied is None:
        supplied = {}
    if not isinstance(supplied, dict):
        raise ValueError("artifacts must be a mapping of artifact name to local path")
    result: dict[str, Path] = {}
    for key, default_name in ARTIFACT_NAMES.items():
        value = supplied.get(key)
        candidates: list[Path] = []
        if isinstance(value, str) and value:
            candidate = Path(value).expanduser()
            if not candidate.is_absolute() and root:
                candidate = root / candidate
            candidates.append(candidate)
        elif value is not None:
            raise ValueError(f"artifact {key} must be a path string")
        if root:
            candidates.extend((root / default_name, root / "input" / default_name))
            if key == "original_log":
                candidates.extend((root / "report.txt", root / "syzbot.txt"))
            if key == "bisection":
                candidates.extend((root / "bisection.log", root / "bisect.txt"))
        resolved_candidates = []
        for candidate in candidates:
            resolved = candidate.resolve()
            if root is not None:
                try:
                    resolved.relative_to(root.resolve())
                except ValueError as exc:
                    raise ValueError(f"artifact {key} escapes the prepared report directory") from exc
            resolved_candidates.append(resolved)
        found = next((candidate for candidate in resolved_candidates if candidate.is_file()), None)
        if found:
            result[key] = found
    return result


def _read_build_id(path: Path) -> tuple[str | None, set[str], str | None]:
    try:
        notes = subprocess.run(["readelf", "-n", str(path)], capture_output=True, text=True,
                               check=False, timeout=15)
        sections = subprocess.run(["readelf", "-S", str(path)], capture_output=True, text=True,
                                  check=False, timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, set(), f"readelf inspection failed: {exc}"
    match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", notes.stdout)
    section_names = set(re.findall(r"\]\s+(\.(?:debug_info|zdebug_info|BTF))\s", sections.stdout))
    if notes.returncode or sections.returncode:
        return None, section_names, "vmlinux is not a readable ELF according to readelf"
    if not match:
        return None, section_names, "vmlinux has no GNU build ID"
    if not ({".debug_info", ".zdebug_info", ".BTF"} & section_names):
        return match.group(1).lower(), section_names, "vmlinux contains neither DWARF .debug_info nor .BTF"
    return match.group(1).lower(), section_names, None


def _elf_architecture(path: Path) -> tuple[str | None, str | None]:
    try:
        result = subprocess.run(["readelf", "-h", str(path)], capture_output=True, text=True,
                                check=False, timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"ELF header inspection failed: {exc}"
    if result.returncode:
        return None, "readelf could not parse ELF header"
    match = re.search(r"^\s*Machine:\s*(.+?)\s*$", result.stdout, re.MULTILINE)
    if not match:
        return None, "ELF machine type is unavailable"
    machine = match.group(1).casefold()
    if "aarch64" in machine:
        return "aarch64", None
    if "x86-64" in machine or "x86_64" in machine:
        return "x86_64", None
    return None, f"unsupported ELF machine type: {match.group(1)}"


def _has_kernel_text_symbols(path: Path) -> bool:
    try:
        result = subprocess.run(["readelf", "-sW", str(path)], capture_output=True, text=True,
                                check=False, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return False
    if result.returncode:
        return False
    names = {line.split()[-1] for line in result.stdout.splitlines() if line.split()}
    return "_stext" in names and "_etext" in names


def _git_commit(tree: Path) -> tuple[str | None, str | None]:
    try:
        result = subprocess.run(["git", "-C", str(tree), "rev-parse", "HEAD"], capture_output=True,
                                text=True, check=False, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, str(exc)
    if result.returncode:
        return None, result.stderr.strip() or "git rev-parse failed"
    return result.stdout.strip().lower(), None


def validate_environment(case: dict[str, Any], input_dir: Path, *, kernel_tree: str | None,
                         vmlinux: str | None, config_provenance: str | None,
                         target_source: str | None = None, target_module: str | None = None,
                         host_architecture: str | None = None, path_env: str | None = None,
                         effective_uid: int | None = None) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    kernel_commit = None
    kernel_release = case.get("kernel_release")
    architecture = _normalized_arch(case.get("architecture"))
    vmlinux_build_id = None
    config_path = input_dir / ".config"
    config_hash = _sha256(config_path) if config_path.is_file() else None
    repro_path = next((input_dir / name for name in ("repro.syz", "repro.c", "repro")
                       if (input_dir / name).is_file()), None)
    reproducer_hash = _sha256(repro_path) if repro_path else None
    repro_executable = False
    env_path = path_env if path_env is not None else os.environ.get("PATH", "")
    if repro_path and os.access(repro_path, os.X_OK):
        repro_executable = True
    elif repro_path and repro_path.name == "repro.syz":
        repro_executable = shutil.which("syz-execprog", path=env_path) is not None

    expected_commit = case.get("kernel_commit")
    if not kernel_tree:
        errors.append("kernel tree was not supplied; commit match cannot be checked")
    else:
        tree = Path(kernel_tree).expanduser().resolve()
        if not tree.is_dir():
            errors.append(f"kernel tree does not exist: {tree}")
        else:
            kernel_commit, git_error = _git_commit(tree)
            if git_error:
                errors.append(f"cannot read kernel tree commit: {git_error}")
            elif not expected_commit:
                errors.append("report kernel_commit is unknown; cannot validate kernel tree")
            else:
                resolved_expected, resolve_error = _git_commit_ref(tree, str(expected_commit))
                if resolve_error or resolved_expected != kernel_commit:
                    errors.append(f"kernel tree commit mismatch: report={expected_commit}, tree={kernel_commit}")
            release_file = tree / "include/config/kernel.release"
            if release_file.is_file():
                tree_release = release_file.read_text(encoding="utf-8", errors="replace").strip()
                if kernel_release and tree_release != kernel_release:
                    errors.append(f"kernel release mismatch: report={kernel_release}, tree={tree_release}")
            elif kernel_release:
                warnings.append("kernel tree release file unavailable; release equality not independently checked")

    if not config_hash:
        errors.append("kernel .config is missing")
    if not (config_provenance or case.get("config_provenance")):
        errors.append(".config provenance is missing")
    sanitizer: dict[str, str] = {}
    if config_hash:
        config_text = config_path.read_text(encoding="utf-8", errors="replace")
        for line in config_text.splitlines():
            match = re.fullmatch(r"(CONFIG_(?:KASAN|KMSAN|KCSAN|KFENCE|UBSAN|KCOV))=(.*)", line)
            if match:
                sanitizer[match.group(1)] = match.group(2)
            else:
                match = re.fullmatch(r"# (CONFIG_(?:KASAN|KMSAN|KCSAN|KFENCE|UBSAN|KCOV)) is not set", line)
                if match:
                    sanitizer[match.group(1)] = "not set"

    if not vmlinux:
        errors.append("vmlinux was not supplied")
    else:
        elf_path = Path(vmlinux).expanduser().resolve()
        if not elf_path.is_file():
            errors.append(f"vmlinux does not exist: {elf_path}")
        else:
            vmlinux_build_id, _, elf_error = _read_build_id(elf_path)
            if elf_error:
                errors.append(elf_error)
            elf_arch, arch_error = _elf_architecture(elf_path)
            if arch_error:
                errors.append(arch_error)
            elif architecture and elf_arch != architecture:
                errors.append(f"vmlinux architecture mismatch: report={architecture}, ELF={elf_arch}")
            if not _has_kernel_text_symbols(elf_path):
                errors.append("vmlinux lacks expected kernel text symbols _stext/_etext")
            expected_id = case.get("vmlinux_build_id") or case.get("kernel_build_id")
            if expected_id and vmlinux_build_id and str(expected_id).lower() != vmlinux_build_id:
                errors.append(f"vmlinux build ID mismatch: report={expected_id}, file={vmlinux_build_id}")
            elif not expected_id and vmlinux_build_id:
                warnings.append("report has no expected vmlinux build ID; ELF ID recorded but exact report match is unavailable")

    actual_arch = _normalized_arch(host_architecture or platform.machine())
    if not architecture:
        errors.append("report architecture is unknown")
    elif architecture != actual_arch:
        errors.append(f"architecture mismatch: report={architecture}, environment={actual_arch}")

    if not repro_path:
        errors.append("syz/C reproducer is absent")
    elif not repro_executable:
        errors.append("reproducer is not executable (C binary must have execute permission; .syz requires syz-execprog)")

    expected_target_commit = case.get("target_source_commit")
    if target_source:
        source_commit, source_error = _git_commit(Path(target_source).expanduser().resolve())
        if source_error:
            errors.append(f"cannot validate target source commit: {source_error}")
        elif expected_target_commit and source_commit != str(expected_target_commit).lower():
            errors.append(f"target source commit mismatch: report={expected_target_commit}, source={source_commit}")
        elif not expected_target_commit:
            warnings.append("target source supplied but report has no expected commit; exact source match is unverified")
    elif expected_target_commit:
        errors.append("report names a target source commit but no target source tree was supplied")
    else:
        warnings.append("target source version was not specified; module/source match is unverified")

    expected_module_id = case.get("target_module_build_id")
    if target_module:
        module_path = Path(target_module).expanduser().resolve()
        if not module_path.is_file():
            errors.append(f"target module does not exist: {module_path}")
        else:
            module_id, _, module_error = _read_build_id(module_path)
            if module_error:
                errors.append(f"target module ELF validation failed: {module_error}")
            elif expected_module_id and module_id != str(expected_module_id).lower():
                errors.append(f"target module build ID mismatch: report={expected_module_id}, file={module_id}")
            elif not expected_module_id:
                warnings.append("target module supplied but report has no expected build ID; exact module match is unverified")
    elif expected_module_id or case.get("target_module"):
        errors.append("report specifies a target module but no matching module ELF was supplied")

    kernel_btf = Path("/sys/kernel/btf/vmlinux").is_file()
    effective_caps = 0
    try:
        status_text = Path("/proc/self/status").read_text(encoding="ascii", errors="replace")
        cap_match = re.search(r"^CapEff:\s*([0-9a-fA-F]+)$", status_text, re.MULTILINE)
        if cap_match:
            effective_caps = int(cap_match.group(1), 16)
    except OSError:
        pass
    uid = os.geteuid() if effective_uid is None else effective_uid
    bpf_privileges = (uid == 0 or bool(effective_caps & (1 << 21)) or
                      (bool(effective_caps & (1 << 39)) and bool(effective_caps & (1 << 38))))
    capture_prerequisites = [
        {"name": "kernel_btf", "available": kernel_btf},
        {"name": "bpftool", "available": shutil.which("bpftool", path=env_path) is not None},
        {"name": "bpf_attach_privileges", "available": bpf_privileges},
        {"name": "tracefs_readable", "available": os.access("/sys/kernel/tracing/events", os.R_OK)},
        {"name": "kernel_tree", "available": bool(kernel_tree and Path(kernel_tree).is_dir())},
    ]
    if not kernel_btf:
        errors.append("kernel BTF is unavailable; RefScope CO-RE capture cannot be validated")
    if not bpf_privileges:
        errors.append("BPF attach privileges are unavailable (need root/CAP_SYS_ADMIN or CAP_BPF+CAP_PERFMON)")
    return {
        "schema_version": SCHEMA_VERSION,
        "valid": not errors,
        "warnings": warnings,
        "errors": errors,
        "kernel_commit": kernel_commit,
        "kernel_release": kernel_release,
        "architecture": architecture,
        "vmlinux_build_id": vmlinux_build_id,
        "config_hash": config_hash,
        "reproducer_hash": reproducer_hash,
        "reproducer_executable": repro_executable,
        "config_provenance": config_provenance or case.get("config_provenance"),
        "sanitizer_configuration": sanitizer,
        "capture_prerequisites": capture_prerequisites,
        "reproduction_started": False,
    }


def _git_commit_ref(tree: Path, commit: str) -> tuple[str | None, str | None]:
    try:
        result = subprocess.run(["git", "-C", str(tree), "rev-parse", "--verify", f"{commit}^{{commit}}"],
                                capture_output=True, text=True, check=False, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, str(exc)
    if result.returncode:
        return None, result.stderr.strip() or "cannot resolve report commit"
    return result.stdout.strip().lower(), None


def _copy_input(data: dict[str, Any], root: Path | None, source: str, text_path: str | None,
                input_dir: Path) -> dict[str, Any]:
    input_dir.mkdir(parents=True)
    original = Path(text_path) if text_path else None
    original_name = "original-report.json" if original and original.suffix.lower() == ".json" else "original-report.txt"
    if original and original.is_file():
        shutil.copyfile(original, input_dir / original_name)
    elif data.get("report") is not None:
        (input_dir / "original-report.txt").write_text(str(data["report"]), encoding="utf-8")
    bisection_info = data.get("bisection_information", data.get("bisection"))
    if bisection_info is not None and not isinstance(bisection_info, str):
        bisection_info = json.dumps(bisection_info, indent=2, sort_keys=True)
    if isinstance(bisection_info, str) and bisection_info and not (input_dir / "bisection.txt").exists():
        suffix = "" if bisection_info.endswith("\n") else "\n"
        (input_dir / "bisection.txt").write_text(bisection_info + suffix, encoding="utf-8")
    (input_dir / "metadata.json").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    artifacts = _artifact_sources(data, root)
    copied: dict[str, dict[str, str]] = {}
    for key, path in artifacts.items():
        name = ARTIFACT_NAMES[key]
        if key == "original_log":
            name = "crash.log"
        destination = input_dir / name
        if path.resolve() != destination.resolve():
            shutil.copyfile(path, destination)
        copied[key] = {"path": f"input/{name}", "sha256": _sha256(destination)}
    for key, fallback in (("config", ".config"), ("syz_reproducer", "repro.syz"),
                          ("c_reproducer", "repro.c"), ("bisection", "bisection.txt")):
        path = input_dir / fallback
        if path.is_file():
            copied.setdefault(key, {"path": f"input/{fallback}", "sha256": _sha256(path)})
    report_file = input_dir / original_name
    if report_file.is_file():
        copied["original_report"] = {"path": f"input/{original_name}", "sha256": _sha256(report_file)}
    return copied


def import_case(source: str, *, cases_dir: str = "cases", kernel_tree: str | None = None,
                vmlinux: str | None = None, config_provenance: str | None = None,
                target_source: str | None = None, target_module: str | None = None,
                report_url: str | None = None, host_architecture: str | None = None,
                path_env: str | None = None, effective_uid: int | None = None) -> tuple[Path, dict[str, Any]]:
    data, source_root, source_label, text_path = _load_source(source)
    artifacts = data.get("artifacts", {})
    if artifacts is None:
        artifacts = {}
    if not isinstance(artifacts, dict):
        raise ValueError("artifacts must be a mapping")
    title = data.get("title")
    if title is not None and not isinstance(title, str):
        raise ValueError("title must be a string or null")
    bug_id = data.get("bug_id")
    if bug_id is not None and not isinstance(bug_id, (str, int)):
        raise ValueError("bug_id must be a string, integer, or null")
    identity = str(bug_id) if bug_id is not None else (title or Path(source).name or "case")
    case_id = _clean_id(identity)
    _artifact_sources(data, source_root)
    destination = Path(cases_dir).expanduser().resolve() / case_id
    if destination.exists():
        raise ValueError(f"case directory already exists: {destination}")
    destination.mkdir(parents=True)
    input_dir = destination / "input"
    validation_dir = destination / "validation"
    validation_dir.mkdir()
    copied = _copy_input(data, source_root, source_label, text_path, input_dir)
    normalized = {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "title": title,
        "report_url": report_url or data.get("report_url") or data.get("url"),
        "source": source_label,
        "kernel_commit": data.get("kernel_commit"),
        "kernel_release": data.get("kernel_release"),
        "architecture": data.get("architecture", data.get("arch")),
        "compiler": data.get("compiler"),
        "config_provenance": config_provenance or data.get("config_provenance"),
        "vmlinux_build_id": data.get("vmlinux_build_id"),
        "kernel_build_id": data.get("kernel_build_id"),
        "target_source_commit": data.get("target_source_commit"),
        "target_module_build_id": data.get("target_module_build_id"),
        "target_module": data.get("target_module"),
        "bisection_information": data.get("bisection_information", data.get("bisection")),
        "sanitizer_configuration_reported": data.get("sanitizer_configuration"),
        "input_files": copied,
        "extra_fields": {key: value for key, value in data.items() if key not in KNOWN_FIELDS},
    }
    validation = validate_environment(
        normalized, input_dir, kernel_tree=kernel_tree, vmlinux=vmlinux,
        config_provenance=config_provenance, target_source=target_source,
        target_module=target_module, host_architecture=host_architecture, path_env=path_env,
        effective_uid=effective_uid,
    )
    normalized["sanitizer_configuration"] = validation["sanitizer_configuration"]
    normalized["environment_validation"] = "validation/result.json"
    normalized["reproduction_blocked"] = not validation["valid"]
    normalized["reproduction_started"] = False
    (destination / "case.json").write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (validation_dir / "result.json").write_text(json.dumps(validation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (validation_dir / "report.txt").write_text(render_validation(validation), encoding="utf-8")
    (destination / "README.md").write_text(render_readme(normalized, validation), encoding="utf-8")
    return destination, validation


def render_validation(result: dict[str, Any]) -> str:
    lines = ["Environment validation: " + ("VALID" if result["valid"] else "BLOCKED"), "",
             f"Kernel commit: {result.get('kernel_commit') or 'unknown'}",
             f"Kernel release: {result.get('kernel_release') or 'unknown'}",
             f"Architecture: {result.get('architecture') or 'unknown'}",
             f"vmlinux build ID: {result.get('vmlinux_build_id') or 'unknown'}",
             f".config SHA-256: {result.get('config_hash') or 'unavailable'}",
             f"Reproducer SHA-256: {result.get('reproducer_hash') or 'unavailable'}",
             f"Reproducer executable: {'yes' if result.get('reproducer_executable') else 'no'}",
             "", "Capture prerequisites:"]
    lines.extend(f"  {'available' if item['available'] else 'unavailable'}: {item['name']}"
                 for item in result.get("capture_prerequisites", []))
    if result.get("warnings"):
        lines.extend(["", "Warnings:", *[f"  - {item}" for item in result["warnings"]]])
    if result.get("errors"):
        lines.extend(["", "Blocking errors:", *[f"  - {item}" for item in result["errors"]],
                      "", "Reproducer was not executed."])
    else:
        lines.extend(["", "Reproducer was not executed by intake."])
    return "\n".join(lines) + "\n"


def render_readme(case: dict[str, Any], validation: dict[str, Any]) -> str:
    def known(value):
        return str(value) if value not in (None, "") else "unknown"
    return (f"# Case {case['case_id']}\n\n"
            f"Title: {known(case.get('title'))}\n\n"
            f"Source: {known(case.get('report_url') or case.get('source'))}\n\n"
            f"Environment validation: {'VALID' if validation['valid'] else 'BLOCKED'}\n\n"
            "Intake stores evidence only. It does not execute reproducers, load modules, "
            "build a kernel, or modify the host. See `validation/report.txt` and `input/`.\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="refscope syzbot", description="Import a local syzbot report without network access")
    parser.add_argument("source", help="local report/directory, syzbot ID, or report URL (URL is recorded, not fetched)")
    parser.add_argument("--cases-dir", default="cases")
    parser.add_argument("--kernel-tree")
    parser.add_argument("--vmlinux")
    parser.add_argument("--config-provenance", help="describe where the supplied .config came from")
    parser.add_argument("--target-source")
    parser.add_argument("--target-module")
    parser.add_argument("--report-url")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        case_dir, validation = import_case(
            args.source, cases_dir=args.cases_dir, kernel_tree=args.kernel_tree,
            vmlinux=args.vmlinux, config_provenance=args.config_provenance,
            target_source=args.target_source, target_module=args.target_module,
            report_url=args.report_url,
        )
    except (OSError, ValueError) as exc:
        print(f"refscope: syzbot intake error: {exc}", file=sys.stderr)
        return 2
    case = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    if args.format == "json":
        print(json.dumps({"case_dir": str(case_dir), "case": case, "validation": validation}, indent=2, sort_keys=True))
    else:
        print(f"Case imported: {case_dir}")
        print(f"Title: {case.get('title') or 'unknown'}")
        print(f"Environment validation: {'VALID' if validation['valid'] else 'BLOCKED'}")
        print(f"Validation report: {case_dir / 'validation/report.txt'}")
        if validation["warnings"]:
            print("Warnings:")
            print("\n".join(f"  - {item}" for item in validation["warnings"]))
        if validation["errors"]:
            print("Blocking errors:")
            print("\n".join(f"  - {item}" for item in validation["errors"]))
        print("Reproducer was not executed.")
    return 0 if validation["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
