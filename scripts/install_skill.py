#!/usr/bin/env python3
"""Copy a reviewed skill into the vault only if it still matches the reviewed hash. Never executes the source."""
import argparse
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# python3 -I removes the script directory from sys.path. Add only this trusted directory back.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_skill import iter_entries, tree_sha256  # noqa: E402

NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
COMMIT = re.compile(r"[0-9a-f]{40}")


class InstallError(Exception):
    pass


def frontmatter(skill_md):
    if not skill_md.is_file():
        raise InstallError("SKILL.md is missing")
    match = re.match(r"---\n(.*?)\n---(\n|$)", skill_md.read_text(encoding="utf-8"), re.DOTALL)
    if not match:
        raise InstallError("SKILL.md frontmatter is invalid")
    fields = dict(re.findall(r"^(name|description):[ \t]*(\S.*)$", match.group(1), re.MULTILINE))
    if "name" not in fields or "description" not in fields:
        raise InstallError("SKILL.md frontmatter needs name and description")
    return fields


def install(source, target_root, name, repo_url, subpath, commit, expected_tree):
    source, target_root = Path(source), Path(target_root)
    if not NAME.fullmatch(name):
        raise InstallError(f"invalid skill name: {name!r}")
    if not COMMIT.fullmatch(commit):
        raise InstallError("commit must be a full 40-character hash")
    if not repo_url.startswith("https://"):
        raise InstallError("repo URL must use https")
    dest = target_root / name
    staging = None
    try:
        if dest.is_symlink() or dest.exists():
            raise InstallError(f"target already exists: {dest}")
        entries = iter_entries(source)
        if any(p.is_symlink() for p in entries):
            raise InstallError("source contains a symlink")
        if any(not (p.is_symlink() or p.is_file()) for p in entries):
            raise InstallError("source contains a special file (FIFO, socket or device)")
        if tree_sha256(source) != expected_tree:
            raise InstallError("tree_sha256 differs from the reviewed content")
        declared = frontmatter(source / "SKILL.md")["name"].strip("'\"")
        if declared != name:
            raise InstallError(f"SKILL.md name {declared!r} differs from {name!r}")

        staging = Path(tempfile.mkdtemp(prefix=f".{name}.tmp-", dir=target_root))
        for path in entries:
            if not stat.S_ISREG(os.lstat(path).st_mode):
                raise InstallError(f"source entry is no longer a regular file: {path.relative_to(source)}")
            copy = staging / path.relative_to(source)
            copy.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, copy)
        if tree_sha256(staging) != expected_tree:
            raise InstallError("tree_sha256 of the copy differs from the reviewed content")
        meta = {"repo_url": repo_url, "subpath": subpath, "commit": commit, "tree_sha256": expected_tree,
                "installed_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        (staging / ".vendored-from.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        staging.chmod(0o755)
        staging.rename(dest)
    except BaseException as error:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        if isinstance(error, OSError):
            raise InstallError(f"I/O failure while installing: {error}") from error
        raise
    return dest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("--source", "--target-root", "--name", "--repo-url", "--subpath", "--commit", "--expected-tree-sha256"):
        parser.add_argument(flag, required=True)
    args = parser.parse_args()
    try:
        dest = install(args.source, args.target_root, args.name, args.repo_url, args.subpath, args.commit, args.expected_tree_sha256)
    except InstallError as error:
        print(f"refused: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"installed": str(dest)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
