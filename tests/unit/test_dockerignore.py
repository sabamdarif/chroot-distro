# The `.dockerignore` matcher, against Docker's own rules. What a pattern means
# decides which files reach the image, and the direction that hurts is
# over-ignoring: a file the author expected in the image is missing from it, with
# nothing in the build output saying so. `fnmatch` did exactly that, its `*`
# crossing `/`, so these tests pin the separator rule first.

from chroot_distro.helpers.build_engine import dockerignore


def _ignored(rel, *patterns):
    return dockerignore.is_ignored(rel, list(patterns))


# ── cleaning a line ───────────────────────────────────────────────────────────
def test_a_line_is_cleaned_the_way_docker_cleans_one(tmp_path):
    (tmp_path / ".dockerignore").write_text(
        "﻿# a comment\n"
        "\n"
        "   \n"
        "  node_modules  \n"
        "/build\n"
        "./docs/\n"
        "!  keep.log\n"
        "!\n"
        "  #keep\n"
    )

    assert dockerignore.load_dockerignore(str(tmp_path)) == [
        "node_modules",
        "build",
        "docs",
        "!keep.log",
        "#keep",
    ]


def test_a_missing_file_means_no_patterns(tmp_path):
    assert dockerignore.load_dockerignore(str(tmp_path)) == []


def test_a_root_relative_pattern_is_the_same_pattern(tmp_path):
    assert dockerignore.clean_pattern("/build") == "build"
    assert dockerignore.clean_pattern("!/build/") == "!build"
    assert _ignored("build/out.o", "/build") is True
    assert _ignored("src/build/out.o", "/build") is False


# ── the separator rule ────────────────────────────────────────────────────────
def test_a_star_does_not_cross_a_separator():
    assert _ignored("app.log", "*.log") is True
    assert _ignored("docs/app.log", "*.log") is False
    assert _ignored("src/a", "src/*") is True
    assert _ignored("src/a/b", "src/*") is True  # via its parent `src/a`
    assert _ignored("src/a/b", "src/*/") is True


def test_a_question_mark_is_one_character_and_not_a_separator():
    assert _ignored("a.c", "?.c") is True
    assert _ignored("ab.c", "?.c") is False
    assert _ignored("a/c", "?.c") is False


def test_a_character_class_still_means_a_range():
    assert _ignored("a1.log", "a[0-9].log") is True
    assert _ignored("ax.log", "a[0-9].log") is False


def test_a_pattern_that_cannot_compile_ignores_nothing():
    assert _ignored("a.txt", "[abc") is False


# ── ** across segments ────────────────────────────────────────────────────────
def test_double_star_spans_any_number_of_segments():
    assert _ignored("c.py", "**/c.py") is True
    assert _ignored("a/b/c.py", "**/c.py") is True
    assert _ignored("a/b/c.pyc", "**/c.py") is False
    assert _ignored("docs/a.md", "**/*.md") is True
    assert _ignored("a/b/keep", "a/**/keep") is True
    assert _ignored("a/keep", "a/**/keep") is True


def test_a_trailing_double_star_covers_the_rest_of_the_path():
    assert _ignored("build/a/b.o", "build/**") is True
    assert _ignored("build", "build/**") is False
    assert _ignored("anything/at/all", "**") is True


# ── directories, negation and order ───────────────────────────────────────────
def test_naming_a_directory_covers_everything_under_it():
    assert _ignored("node_modules", "node_modules") is True
    assert _ignored("node_modules/lib/x.js", "node_modules") is True


def test_the_last_pattern_to_match_decides():
    assert _ignored("keep.log", "*.log", "!keep.log") is False
    assert _ignored("keep.log", "!keep.log", "*.log") is True
    assert _ignored("a.log", "*.log", "!keep.log") is True


def test_a_child_of_an_ignored_directory_can_be_re_included():
    patterns = ["node_modules", "!node_modules/keep.js"]
    assert _ignored("node_modules/keep.js", *patterns) is False
    assert _ignored("node_modules/other.js", *patterns) is True


def test_the_dockerfile_and_the_ignore_file_are_never_ignored():
    assert _ignored("Dockerfile", "*") is False
    assert _ignored(".dockerignore", "*") is False


def test_the_context_root_is_never_ignored():
    assert _ignored(".", "*") is False


def test_no_patterns_ignores_nothing():
    assert dockerignore.is_ignored("a.txt", []) is False
