import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
import audit_skill  # noqa: E402
import install_skill  # noqa: E402

COMMIT = "a" * 40
REPO = "https://github.com/example-org/sample"


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.source = self.base / "src"
        self.target = self.base / "vault"
        self.source.mkdir()
        self.target.mkdir()
        (self.source / "SKILL.md").write_text("---\nname: sample\ndescription: Sample text.\n---\nBody\n", encoding="utf-8")

    def run_install(self, **overrides):
        args = dict(source=self.source, target_root=self.target, name="sample", repo_url=REPO, subpath=".",
                    commit=COMMIT, expected_tree=audit_skill.tree_sha256(self.source))
        args.update(overrides)
        return install_skill.install(**args)


class TestInstall(Base):
    def test_copies_files_and_records_source(self):
        (self.source / "refs").mkdir()
        (self.source / "refs/a.md").write_text("x", encoding="utf-8")
        dest = self.run_install()
        self.assertEqual(dest, self.target / "sample")
        self.assertEqual((dest / "refs/a.md").read_text(encoding="utf-8"), "x")
        meta = json.loads((dest / ".vendored-from.json").read_text(encoding="utf-8"))
        self.assertEqual((meta["repo_url"], meta["subpath"], meta["commit"]), (REPO, ".", COMMIT))
        self.assertEqual(meta["tree_sha256"], audit_skill.tree_sha256(self.source))
        self.assertIn("installed_at", meta)

    def test_git_dir_not_copied(self):
        (self.source / ".git").mkdir()
        (self.source / ".git/config").write_text("x", encoding="utf-8")
        self.assertFalse((self.run_install() / ".git").exists())

    def test_exec_bit_preserved(self):
        p = self.source / "run.sh"
        p.write_text("x", encoding="utf-8")
        p.chmod(0o755)
        self.assertTrue(os.access(self.run_install() / "run.sh", os.X_OK))


class TestRefusals(Base):
    def assert_refused(self, **overrides):
        with self.assertRaises(install_skill.InstallError):
            self.run_install(**overrides)
        self.assertEqual([p for p in self.target.iterdir() if p.name != "sample"], [])

    def test_tree_mismatch(self):
        self.assert_refused(expected_tree="0" * 64)
        self.assertFalse((self.target / "sample").exists())

    def test_path_escape_name(self):
        for name in ("../evil", "a/b", ".hidden", "", "UPPER"):
            with self.subTest(name=name):
                self.assert_refused(name=name)

    def test_existing_target(self):
        (self.target / "sample").mkdir()
        self.assert_refused()
        self.assertEqual(list((self.target / "sample").iterdir()), [])

    def test_symlink_in_source(self):
        os.symlink("SKILL.md", self.source / "link.md")
        self.assert_refused()

    def test_special_file_in_source(self):
        os.mkfifo(self.source / "pipe")
        self.assert_refused()

    def test_unreadable_file_refused(self):
        if os.geteuid() == 0:
            self.skipTest("root can read mode 000 files")
        secret = self.source / "secret.txt"
        secret.write_text("x", encoding="utf-8")
        secret.chmod(0o000)
        self.addCleanup(secret.chmod, 0o644)
        self.assert_refused()

    def test_missing_skill_md(self):
        (self.source / "SKILL.md").unlink()
        self.assert_refused()

    def test_invalid_frontmatter(self):
        (self.source / "SKILL.md").write_text("no frontmatter", encoding="utf-8")
        self.assert_refused()

    def test_non_utf8_skill_md(self):
        (self.source / "SKILL.md").write_bytes(b"\xff\xfe")
        self.assert_refused()

    def test_missing_description(self):
        (self.source / "SKILL.md").write_text("---\nname: sample\n---\n", encoding="utf-8")
        self.assert_refused()

    def test_name_mismatch(self):
        (self.source / "SKILL.md").write_text("---\nname: other\ndescription: Text.\n---\n", encoding="utf-8")
        self.assert_refused()

    def test_bad_commit(self):
        self.assert_refused(commit="main")

    def test_non_https_repo(self):
        self.assert_refused(repo_url="ssh://example.invalid/x")


class TestCli(Base):
    def cli(self, expected):
        return subprocess.run(
            [sys.executable, "-I", str(SCRIPTS / "install_skill.py"), "--source", str(self.source),
             "--target-root", str(self.target), "--name", "sample", "--repo-url", REPO, "--subpath", ".",
             "--commit", COMMIT, "--expected-tree-sha256", expected, "--repo-root", str(self.base)],
            capture_output=True, text=True, cwd=self.source)

    def test_success(self):
        out = self.cli(audit_skill.tree_sha256(self.source))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout)["installed"], str(self.target / "sample"))

    def test_refusal(self):
        out = self.cli("0" * 64)
        self.assertEqual(out.returncode, 1)
        self.assertIn("tree_sha256", out.stderr)


class TestRepoRoot(Base):
    def test_symlinked_source_refused_with_repo_root(self):
        real = self.base / "real"
        real.mkdir()
        (real / "SKILL.md").write_text("---\nname: sample\ndescription: Sample text.\n---\n", encoding="utf-8")
        os.symlink(real, self.base / "alias")
        with self.assertRaises(install_skill.InstallError):
            self.run_install(source=self.base / "alias", repo_root=self.base,
                             expected_tree=audit_skill.tree_sha256(real))

    def test_source_outside_repo_root_refused(self):
        other = self.base / "other"
        other.mkdir()
        with self.assertRaises(install_skill.InstallError):
            self.run_install(repo_root=other)

    def test_source_inside_repo_root_installs(self):
        self.assertTrue(self.run_install(repo_root=self.base).is_dir())

    def test_cli_requires_repo_root(self):
        out = subprocess.run(
            [sys.executable, "-I", str(SCRIPTS / "install_skill.py"), "--source", str(self.source),
             "--target-root", str(self.target), "--name", "sample", "--repo-url", REPO, "--subpath", ".",
             "--commit", COMMIT, "--expected-tree-sha256", audit_skill.tree_sha256(self.source)],
            capture_output=True, text=True)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("repo-root", out.stderr)

    def test_cli_repo_root_failure_is_refusal(self):
        other = self.base / "other"
        other.mkdir()
        out = subprocess.run(
            [sys.executable, "-I", str(SCRIPTS / "install_skill.py"), "--source", str(self.source),
             "--target-root", str(self.target), "--name", "sample", "--repo-url", REPO, "--subpath", ".",
             "--commit", COMMIT, "--expected-tree-sha256", audit_skill.tree_sha256(self.source),
             "--repo-root", str(other)],
            capture_output=True, text=True)
        self.assertEqual(out.returncode, 1)
        self.assertIn("refused", out.stderr)


class TestVendoredMetadataInSource(Base):
    def test_source_with_metadata_file_refused(self):
        (self.source / ".vendored-from.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(install_skill.InstallError):
            self.run_install()
        self.assertEqual(list(self.target.iterdir()), [])


class TestVerify(Base):
    def setUp(self):
        super().setUp()
        (self.source / "refs").mkdir()
        (self.source / "refs/a.md").write_text("x", encoding="utf-8")
        self.tree = audit_skill.tree_sha256(self.source)
        self.dest = self.run_install()

    def test_success(self):
        self.assertEqual(install_skill.verify(self.dest, self.tree), self.dest)

    def test_changed_file(self):
        (self.dest / "refs/a.md").write_text("y", encoding="utf-8")
        with self.assertRaises(install_skill.InstallError):
            install_skill.verify(self.dest, self.tree)

    def test_missing_file(self):
        (self.dest / "refs/a.md").unlink()
        with self.assertRaises(install_skill.InstallError):
            install_skill.verify(self.dest, self.tree)

    def test_missing_metadata(self):
        (self.dest / ".vendored-from.json").unlink()
        with self.assertRaises(install_skill.InstallError):
            install_skill.verify(self.dest, self.tree)

    def test_metadata_hash_mismatch(self):
        meta = self.dest / ".vendored-from.json"
        data = json.loads(meta.read_text(encoding="utf-8"))
        data["tree_sha256"] = "0" * 64
        meta.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(install_skill.InstallError):
            install_skill.verify(self.dest, self.tree)

    def test_cli_verify(self):
        run = lambda h: subprocess.run([sys.executable, "-I", str(SCRIPTS / "install_skill.py"), "--verify", str(self.dest),
                                        "--expected-tree-sha256", h], capture_output=True, text=True)
        ok = run(self.tree)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual(json.loads(ok.stdout)["verified"], str(self.dest))
        bad = run("0" * 64)
        self.assertEqual(bad.returncode, 1)
        self.assertIn("refused", bad.stderr)


class TestRootSkill(Base):
    def cli(self, subpath):
        return subprocess.run(
            [sys.executable, "-I", str(SCRIPTS / "install_skill.py"), "--source", str(self.source) + "/.",
             "--target-root", str(self.target), "--name", "sample", "--repo-url", REPO, "--subpath", subpath,
             "--commit", COMMIT, "--expected-tree-sha256", audit_skill.tree_sha256(self.source),
             "--repo-root", str(self.source)],
            capture_output=True, text=True)

    def test_dot_subpath(self):
        out = self.cli(".")
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_empty_subpath(self):
        out = self.cli("")
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_root_dot_passes_check_and_installs(self):
        audit_skill.check_source(self.source, self.source / ".")
        self.assertTrue(self.run_install(source=self.source / ".", repo_root=self.source).is_dir())


if __name__ == "__main__":
    unittest.main()
