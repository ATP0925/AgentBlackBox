"""Unit tests for PR diff parsing, file filtering, and line-to-hunk position mapping."""

from agentblackbox.github_app.config import PathSettings
from agentblackbox.github_app.diff import DiffMapper

SAMPLE_UNIFIED_DIFF = """diff --git a/src/main.py b/src/main.py
index 1111111..2222222 100644
--- a/src/main.py
+++ b/src/main.py
@@ -1,5 +1,6 @@
 def hello():
-    return "old"
+    # modified line
+    return "new"
 
 def unused():
     pass
diff --git a/package-lock.json b/package-lock.json
index 3333333..4444444 100644
--- a/package-lock.json
+++ b/package-lock.json
@@ -1,3 +1,3 @@
-{ "name": "app", "version": "1.0.0" }
+{ "name": "app", "version": "1.0.1" }
"""


def test_should_review_file_filters_lockfiles_and_vendor() -> None:
    mapper = DiffMapper(SAMPLE_UNIFIED_DIFF)

    assert mapper.should_review_file("src/main.py") is True
    assert mapper.should_review_file("src/app.py") is True

    # Lockfiles & vendor must be skipped
    assert mapper.should_review_file("package-lock.json") is False
    assert mapper.should_review_file("poetry.lock") is False
    assert mapper.should_review_file("node_modules/express/index.js") is False
    assert mapper.should_review_file("dist/bundle.min.js") is False


def test_custom_include_and_exclude_paths() -> None:
    path_settings = PathSettings(
        include=["src/**"],
        exclude=["src/generated/**"],
    )
    mapper = DiffMapper(SAMPLE_UNIFIED_DIFF, path_settings=path_settings)

    assert mapper.should_review_file("src/api/auth.py") is True
    assert mapper.should_review_file("docs/index.md") is False
    assert mapper.should_review_file("src/generated/types.py") is False


def test_get_comment_position_in_hunk() -> None:
    mapper = DiffMapper(SAMPLE_UNIFIED_DIFF)

    # Line 2 and Line 3 are inside the hunk in src/main.py
    pos = mapper.get_comment_position("src/main.py", 2)
    assert pos is not None
    assert pos.path == "src/main.py"
    assert pos.line == 2
    assert pos.side == "RIGHT"

    # Line 300 is NOT in any diff hunk -> MUST return None to avoid GitHub 422
    pos_out_of_hunk = mapper.get_comment_position("src/main.py", 300)
    assert pos_out_of_hunk is None

    # Unknown file -> None
    assert mapper.get_comment_position("non_existent.py", 10) is None


def test_chunk_diff_by_token_budget() -> None:
    mapper = DiffMapper(SAMPLE_UNIFIED_DIFF)
    chunked = mapper.chunk_diff_by_token_budget(max_chars=200)

    # Fits or contains truncation marker
    assert len(chunked) <= len(SAMPLE_UNIFIED_DIFF) + 200
