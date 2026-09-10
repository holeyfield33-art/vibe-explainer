import os
import tempfile
import unittest
from pathlib import Path

from vibe_explainer.exclusion_policy import (
    NEVER_EXCLUDE_DIRS,
    classify_dir_exclusion,
    walk_pruned,
)


def _all_rel_files(root: Path) -> set[str]:
    found = set()
    for dirpath, _dirnames, filenames in walk_pruned(root):
        for name in filenames:
            rel = str((Path(dirpath) / name).relative_to(root)).replace("\\", "/")
            found.add(rel)
    return found


class TestGithubDirVisibility(unittest.TestCase):
    """Issue #18: a `.git`-prefix check previously hid `.github` as a side
    effect, silently dropping CI/workflow files from every scan. Exact-name
    exclusion must exclude `.git` while leaving `.github` fully visible."""

    def test_dotgit_excluded_dotgithub_visible(self):
        self.assertTrue(classify_dir_exclusion(".git").excluded)
        self.assertFalse(classify_dir_exclusion(".github").excluded)

    def test_never_exclude_dirs_all_pass_classification(self):
        for name in NEVER_EXCLUDE_DIRS:
            self.assertFalse(
                classify_dir_exclusion(name).excluded,
                f"{name!r} must never be excluded by directory-name policy",
            )

    def test_workflow_file_survives_walk_pruned(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            (root / ".git").mkdir()
            (root / ".git" / "config").write_text("[core]\n")
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "ci.yml").write_text("name: CI\non: [push]\n")

            found = _all_rel_files(root)

            self.assertIn(".github/workflows/ci.yml", found)
            self.assertNotIn(".git/config", found)


class TestDirectorySymlinkPruning(unittest.TestCase):
    """Issue #16: os.walk's default followlinks=False stops recursion into a
    symlinked directory but still leaves the entry in dirnames, so downstream
    code that stat()s/resolve()s through it can read outside the repo root.
    walk_pruned must remove such entries from dirnames outright."""

    @unittest.skipUnless(hasattr(os, "symlink"), "requires symlink support")
    def test_symlinked_directory_is_not_walked_into(self):
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(root_dir)
            outside = Path(outside_dir)
            (outside / "secret.py").write_text("SECRET = 'outside-repo'\n")

            link = root / "linked_dir"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation requires elevated privilege on this platform")

            found = _all_rel_files(root)

            self.assertEqual(found, set())

    @unittest.skipUnless(hasattr(os, "symlink"), "requires symlink support")
    def test_symlinked_directory_removed_from_dirnames(self):
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(root_dir)
            outside = Path(outside_dir)
            (outside / "secret.py").write_text("SECRET = 'outside-repo'\n")

            link = root / "linked_dir"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation requires elevated privilege on this platform")

            top_dirnames = next(walk_pruned(root))[1]

            self.assertNotIn("linked_dir", top_dirnames)


if __name__ == "__main__":
    unittest.main()
