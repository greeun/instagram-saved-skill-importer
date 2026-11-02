#!/usr/bin/env python3
"""Static review of a downloaded skill. Never executes or imports the target."""
import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

HIGH, MEDIUM = "high", "medium"
RULES = (
    (HIGH, "credential-access", r"\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.netrc|find-generic-password|(?<![\w.])\.env(?:rc(?!\w)|(?!\.(?:example|sample|template)(?!\w))(?!\w))"),
    (HIGH, "pipe-to-shell", r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?((ba|z)?sh|python3?|node|perl|ruby)\b|\b(ba|z)?sh\s+(-c\s+)?[\"']?(<\(|\$\()\s*(curl|wget)\b"),
    (HIGH, "encoded-exec", r"\b(exec|eval)\s*\(.*(b64decode|atob|fromCharCode|decompress)|base64\s+(-d|-D|--decode)[^|\n]*\|\s*(ba|z)?sh\b"),
    (HIGH, "encoded-blob", r"[A-Za-z0-9+/_-]{200,}={0,2}"),
    (HIGH, "hidden-unicode", "[​-‏‪-‮⁠-⁤]"),
    (HIGH, "data-upload", r"\bcurl\b.*\s(-d|--data\S*|-F|--form|-T|--upload-file)\s|\bcurl\b.*\s-d@|\bwget\b.*--post-file|\bscp\s|\b(requests|httpx)\.(post|put)\(|urlopen\(.*data=|\bnc\s+-"),
    (HIGH, "prompt-injection", r"(ignore|disregard)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|rules)|(without|do not|don't)\s+(asking|telling|informing|ask|tell|inform)\s+the\s+user|(이전|기존)\s*(지시|지침|규칙).*무시|사용자에게\s*(알리지|말하지|묻지)\s*(말|마)"),
    (MEDIUM, "hook-config", r"\"hooks\"\s*:|PreToolUse|PostToolUse|SessionStart|UserPromptSubmit"),
    (MEDIUM, "global-config", r"\.claude/(settings|CLAUDE)|\.zshrc|\.bashrc|\.zprofile|\.gitconfig|crontab|LaunchAgents"),
    (MEDIUM, "permission-bypass", r"--dangerously-skip-permissions|bypassPermissions|dangerouslyDisableSandbox|--no-verify"),
    (MEDIUM, "package-install", r"\b(pip3?|uv\s+tool|uv\s+pip|cargo|brew)\s+install\b|\bnpm\s+(i|install)\b|\bnpx\s+-y\b"),
)
COMPILED = tuple((s, n, re.compile(p, re.IGNORECASE)) for s, n, p in RULES)
SCRIPT_SUFFIXES = {".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl"}
DOMAIN = re.compile(r"https?://([\w.-]+)")


UNREADABLE_MARKER = b"unreadable"


def iter_entries(root):
    """Every non-directory entry under root (files, symlinks, FIFOs, sockets), sorted by relative path.

    Links are not followed and nothing is opened. Only the top-level .git (file or directory) is skipped.
    """
    root = Path(root)
    found = []
    for cur, dirs, files in os.walk(root, followlinks=False):
        here = Path(cur)
        dirs[:] = [d for d in dirs if not (here == root and d == ".git")]
        for name in dirs + files:
            if here == root and name == ".git":
                continue
            path = here / name
            if path.is_symlink() or not path.is_dir():
                found.append(path)
    return sorted(found, key=lambda p: p.relative_to(root).as_posix())


def _safe(text):
    """Render text that may hold surrogate escapes (non-UTF-8 names) as printable UTF-8."""
    return text.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")


def tree_sha256(root):
    root = Path(root)
    total = hashlib.sha256()
    for path in iter_entries(root):
        total.update(os.fsencode(path.relative_to(root).as_posix()) + b"\0")
        if path.is_symlink():
            total.update(b"L" + os.fsencode(os.readlink(path)) + b"\0")
        elif not stat.S_ISREG(os.lstat(path).st_mode):
            total.update(b"S\0")  # special file: marker only, never opened
        else:
            flag = b"X" if os.stat(path).st_mode & 0o111 else b"F"
            try:
                digest = hashlib.sha256(path.read_bytes()).digest()
            except OSError:
                digest = hashlib.sha256(UNREADABLE_MARKER).digest()
            total.update(flag + digest)
    return total.hexdigest()


def finding(severity, rule, rel, line, evidence):
    return {"severity": severity, "rule": rule, "file": _safe(rel), "line": line, "evidence": _safe(evidence.strip()[:120])}


def logical_lines(lines):
    """Join backslash-continued physical lines; yield (number of the line where it starts, text)."""
    start, parts = None, []
    for number, line in enumerate(lines, 1):
        if start is None:
            start = number
        if line.endswith("\\"):
            parts.append(line[:-1])
            continue
        parts.append(line)
        yield start, " ".join(parts)
        start, parts = None, []
    if parts:
        yield start, " ".join(parts)


def _symlink_finding(root, path, rel):
    link = os.readlink(path)
    try:
        target = (path.parent / link).resolve(strict=True)
        inside = target == root or root in target.parents
    except (OSError, RuntimeError):
        inside = False  # unresolvable (loop, dangling) counts as outside
    if inside:
        return finding(MEDIUM, "symlink-inside", rel, 0, link)
    return finding(HIGH, "symlink-outside", rel, 0, link)


def audit(root):
    root = Path(root).resolve()
    findings, scripts, domains = [], [], set()
    total_bytes = 0
    entries = iter_entries(root)
    for path in entries:
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            findings.append(_symlink_finding(root, path, rel))
            continue
        if not stat.S_ISREG(os.lstat(path).st_mode):
            findings.append(finding(HIGH, "special-file", rel, 0, "not a regular file; not opened"))
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            findings.append(finding(HIGH, "unreadable-file", rel, 0, str(exc)))
            continue
        total_bytes += len(data)
        if path.suffix in SCRIPT_SUFFIXES or os.stat(path).st_mode & 0o111:
            scripts.append(rel)
        if b"\0" in data[:8192]:
            findings.append(finding(MEDIUM, "binary-file", rel, 0, f"{len(data)} bytes"))
        for number, text in logical_lines(data.decode("utf-8", "replace").splitlines()):
            domains.update(DOMAIN.findall(text))
            for severity, rule, pattern in COMPILED:
                if pattern.search(text):
                    findings.append(finding(severity, rule, rel, number, text))
    severities = {f["severity"] for f in findings}
    verdict = HIGH if HIGH in severities else MEDIUM if MEDIUM in severities else "none"
    return {
        "tree_sha256": tree_sha256(root),
        "verdict": verdict,
        "findings": findings,
        "info": {"file_count": len(entries), "total_bytes": total_bytes, "scripts": [_safe(s) for s in scripts], "domains": sorted(domains)},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory")
    args = parser.parse_args()
    if not Path(args.directory).is_dir():
        print(f"not a directory: {args.directory}", file=sys.stderr)
        return 2
    payload = json.dumps(audit(args.directory), ensure_ascii=False, indent=2) + "\n"
    sys.stdout.buffer.write(payload.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
