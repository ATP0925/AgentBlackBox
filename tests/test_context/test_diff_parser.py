"""Unit tests for Git unified diff parser."""

from agentblackbox.context.diff_parser import parse_unified_diff
from agentblackbox.models.diff import DiffLineType


SAMPLE_DIFF = """diff --git a/src/math_utils.py b/src/math_utils.py
index 1122334..5566778 100644
--- a/src/math_utils.py
+++ b/src/math_utils.py
@@ -10,6 +10,8 @@ def divide(a: float, b: float) -> float:
     if b == 0:
-        raise ValueError("Cannot divide by zero")
+        # Safe fallback
+        return 0.0
     return a / b
@@ -25,4 +27,5 @@ def multiply(a: float, b: float) -> float:
     return a * b
+    # Extra trailing line
diff --git a/tests/test_math.py b/tests/test_math.py
new file mode 100644
--- /dev/null
+++ b/tests/test_math.py
@@ -0,0 +1,5 @@
+def test_divide():
+    assert divide(4, 2) == 2.0
"""


def test_parse_unified_diff_multiple_files() -> None:
    diff = parse_unified_diff(SAMPLE_DIFF)
    assert len(diff.files) == 2
    assert diff.changed_files == ["src/math_utils.py", "tests/test_math.py"]

    math_file = diff.get_file("src/math_utils.py")
    assert math_file is not None
    assert math_file.old_path == "src/math_utils.py"
    assert math_file.new_path == "src/math_utils.py"
    assert math_file.is_new is False
    assert len(math_file.hunks) == 2

    # Hunk 1 checks
    hunk1 = math_file.hunks[0]
    assert hunk1.old_start == 10
    assert hunk1.new_start == 10
    assert len(hunk1.added_lines) == 2
    assert hunk1.added_lines[0] == (11, "        # Safe fallback")
    assert hunk1.added_lines[1] == (12, "        return 0.0")

    # Touches line check
    assert math_file.touches_line(11) is True
    assert math_file.touches_line(28) is True
    assert math_file.touches_line(999) is False

    # New file checks
    test_file = diff.get_file("tests/test_math.py")
    assert test_file is not None
    assert test_file.is_new is True
    assert test_file.old_path is None
    assert len(test_file.hunks) == 1
    assert len(test_file.get_added_line_numbers()) == 2


def test_parse_empty_diff() -> None:
    diff = parse_unified_diff("")
    assert len(diff.files) == 0
    assert diff.changed_files == []


def test_parse_binary_diff() -> None:
    raw = """diff --git a/logo.png b/logo.png
Binary files a/logo.png and b/logo.png differ
"""
    diff = parse_unified_diff(raw)
    assert len(diff.files) == 1
    assert diff.files[0].is_binary is True
