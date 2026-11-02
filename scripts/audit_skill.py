#!/usr/bin/env python3
"""Static review of a downloaded skill. Never executes or imports the target."""
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

HIGH, MEDIUM = "high", "medium"
RULES = (
    (HIGH, "credential-access", r"\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.netrc|find-generic-password|(?<![\w.])\.env(?![\w.])"),
    (HIGH, "pipe-to-shell", r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh\b"),
    (HIGH, "encoded-exec", r"\b(exec|eval)\s*\(.*(b64decode|atob|fromCharCode|decompress)|base64\s+(-d|-D|--decode)[^|\n]*\|\s*(ba|z)?sh\b"),
    (HIGH, "encoded-blob", r"[A-Za-z0-9+/]{200,}={0,2}"),
    (HIGH, "hidden-unicode", "[​-‏‪-‮⁠-⁤]"),
    (HIGH, "data-upload", r"\bcurl\b.*\s(-d|--data\S*|-F|--form|-T|--upload-file)\s|\b(requests|httpx)\.(post|put)\(|urlopen\(.*data=|\bnc\s+-"),
    (HIGH, "prompt-injection", r"(ignore|disregard)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|rules)|(without|do not|don't)\s+(asking|telling|informing|ask|tell|inform)\s+the\s+user|(이전|기존)\s*(지시|지침|규칙).*무시|사용자에게\s*(알리지|말하지|묻지)\s*(말|마)"),
    (MEDIUM, "hook-config", r"\"hooks\"\s*:|PreToolUse|PostToolUse|SessionStart|UserPromptSubmit"),
    (MEDIUM, "global-config", r"\.claude/(settings|CLAUDE)|\.zshrc|\.bashrc|\.zprofile|\.gitconfig|crontab|LaunchAgents"),
    (MEDIUM, "permission-bypass", r"--dangerously-skip-permissions|bypassPermissions|dangerouslyDisableSandbox|--no-verify"),
    (MEDIUM, "package-install", r"\b(pip3?|uv\s+tool|uv\s+pip|cargo|brew)\s+install\b|\bnpm\s+(i|install)\b|\bnpx\s+-y\b"),
)
COMPILED = tuple((s, n, re.compile(p, re.IGNORECASE)) for s, n, p in RULES)
SCRIPT_SUFFIXES = {".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl"}
DOMAIN = re.compile(r"https?://([\w.-]+)")


def iter_entries(root):
    """Files and symlinks under root, sorted by relative path, without following links or entering .git."""
    root = Path(root)
    found = []
    for cur, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d != ".git"]
        for name in dirs + files:
            path = Path(cur) / name
            if name != ".git" and (path.is_symlink() or path.is_file()):
                found.append(path)
    return sorted(found, key=lambda p: p.relative_to(root).as_posix())


def tree_sha256(root):
    root = Path(root)
    total = hashlib.sha256()
    for path in iter_entries(root):
        total.update(path.relative_to(root).as_posix().encode() + b"\0")
        if path.is_symlink():
            total.update(b"L" + os.readlink(path).encode() + b"\0")
        else:
            flag = b"X" if os.stat(path).st_mode & 0o111 else b"F"
            total.update(flag + hashlib.sha256(path.read_bytes()).digest())
    return total.hexdigest()


def finding(severity, rule, rel, line, evidence):
    return {"severity": severity, "rule": rule, "file": rel, "line": line, "evidence": evidence.strip()[:120]}


def audit(root):
    root = Path(root).resolve()
    findings, scripts, domains = [], [], set()
    total_bytes = 0
    entries = iter_entries(root)
    for path in entries:
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            target = (path.parent / os.readlink(path)).resolve()
            inside = target == root or root in target.parents
            findings.append(finding(MEDIUM if inside else HIGH, "symlink-inside" if inside else "symlink-outside", rel, 0, os.readlink(path)))
            continue
        data = path.read_bytes()
        total_bytes += len(data)
        if path.suffix in SCRIPT_SUFFIXES or os.stat(path).st_mode & 0o111:
            scripts.append(rel)
        if b"\0" in data[:8192]:
            findings.append(finding(MEDIUM, "binary-file", rel, 0, f"{len(data)} bytes"))
            continue
        for number, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
            domains.update(DOMAIN.findall(line))
            for severity, rule, pattern in COMPILED:
                if pattern.search(line):
                    findings.append(finding(severity, rule, rel, number, line))
    severities = {f["severity"] for f in findings}
    verdict = HIGH if HIGH in severities else MEDIUM if MEDIUM in severities else "none"
    return {
        "tree_sha256": tree_sha256(root),
        "verdict": verdict,
        "findings": findings,
        "info": {"file_count": len(entries), "total_bytes": total_bytes, "scripts": scripts, "domains": sorted(domains)},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory")
    args = parser.parse_args()
    if not Path(args.directory).is_dir():
        print(f"not a directory: {args.directory}", file=sys.stderr)
        return 2
    json.dump(audit(args.directory), sys.stdout, ensure_ascii=False, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
