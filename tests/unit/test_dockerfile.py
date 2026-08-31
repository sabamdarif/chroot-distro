import pytest

from chroot_distro.helpers.dockerfile import (
    DockerfileSyntaxError,
    expand_vars,
    parse_dockerfile,
)


def test_parse_dockerfile_basic():
    content = """
# syntax=docker/dockerfile:1
# escape=\\

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl
CMD ["python3", "-m", "http.server"]
"""
    directives, instructions = parse_dockerfile(content)
    assert directives == {"syntax": "docker/dockerfile:1", "escape": "\\"}
    assert len(instructions) == 3

    assert instructions[0]["name"] == "FROM"
    assert instructions[0]["value"] == "ubuntu:22.04"
    assert instructions[0]["exec_form"] is False

    assert instructions[1]["name"] == "RUN"
    assert instructions[1]["value"] == "apt-get update && apt-get install -y curl"
    assert instructions[1]["exec_form"] is False

    assert instructions[2]["name"] == "CMD"
    assert instructions[2]["value"] == ["python3", "-m", "http.server"]
    assert instructions[2]["exec_form"] is True


def test_parse_dockerfile_escape_directive():
    # Test alternative escape character
    content = """# escape=`
FROM alpine
RUN echo `
    hello
"""
    directives, instructions = parse_dockerfile(content)
    assert directives == {"escape": "`"}
    assert len(instructions) == 2
    assert instructions[1]["name"] == "RUN"
    assert instructions[1]["value"] == "echo hello"


def test_parse_dockerfile_line_continuations_and_comments():
    content = r"""
FROM debian
# This is a comment
RUN echo \
    # comment inside continuation
    first \
    second
"""
    _, instructions = parse_dockerfile(content)
    assert len(instructions) == 2
    assert instructions[1]["name"] == "RUN"
    assert instructions[1]["value"] == "echo first second"


def test_parse_dockerfile_flags():
    content = """
COPY --chown=1000:1000 --chmod=644 src/ /app/
COPY --chmod="0755" file.sh /usr/bin/
"""
    _, instructions = parse_dockerfile(content)
    assert len(instructions) == 2

    assert instructions[0]["name"] == "COPY"
    assert instructions[0]["flags"] == {"chown": "1000:1000", "chmod": "644"}
    assert instructions[0]["value"] == "src/ /app/"

    assert instructions[1]["name"] == "COPY"
    assert instructions[1]["flags"] == {"chmod": "0755"}
    assert instructions[1]["value"] == "file.sh /usr/bin/"


def test_parse_dockerfile_repeated_mount_flags_collected():
    content = "RUN --mount=type=cache,target=/a --mount=type=tmpfs,target=/b --network=host make\n"
    _, instructions = parse_dockerfile(content)
    (instr,) = instructions
    assert instr["flags"]["mount"] == ["type=cache,target=/a", "type=tmpfs,target=/b"]
    assert instr["flags"]["network"] == "host"
    assert instr["value"] == "make"


def test_parse_dockerfile_single_mount_flag_stays_string():
    _, instructions = parse_dockerfile("RUN --mount=type=cache,target=/a make\n")
    assert instructions[0]["flags"]["mount"] == "type=cache,target=/a"


def test_parse_dockerfile_repeated_nonmount_flag_last_wins():
    _, instructions = parse_dockerfile("COPY --chmod=644 --chmod=755 a /b\n")
    assert instructions[0]["flags"]["chmod"] == "755"


def test_parse_dockerfile_from_platform_stays_unexpanded():
    # The engine expands a FROM against the global ARG scope, so the parser has
    # to hand the expression over as written.
    _, instructions = parse_dockerfile('FROM --platform="$BUILDPLATFORM" golang:1.22 AS builder\n')
    (instr,) = instructions
    assert instr["flags"] == {"platform": "$BUILDPLATFORM"}
    assert instr["value"] == "golang:1.22 AS builder"


def test_parse_dockerfile_from_platform_without_a_value():
    _, instructions = parse_dockerfile("FROM --platform alpine\n")
    assert instructions[0]["flags"] == {"platform": ""}
    assert instructions[0]["value"] == "alpine"


def test_parse_dockerfile_onbuild():
    content = "ONBUILD RUN echo nested"
    _, instructions = parse_dockerfile(content)
    assert len(instructions) == 1
    assert instructions[0]["name"] == "ONBUILD"

    inner = instructions[0]["value"]
    assert isinstance(inner, dict)
    assert inner["name"] == "RUN"
    assert inner["value"] == "echo nested"


def test_parse_dockerfile_heredocs():
    content = """
RUN <<EOF
echo "hello"
echo "world"
EOF

RUN <<-EOF
\techo "tabs stripped"
\tEOF
"""
    _, instructions = parse_dockerfile(content)
    assert len(instructions) == 2

    assert instructions[0]["name"] == "RUN"
    assert len(instructions[0]["heredocs"]) == 1
    assert instructions[0]["heredocs"][0]["tag"] == "EOF"
    assert instructions[0]["heredocs"][0]["strip_indent"] is False
    assert instructions[0]["heredocs"][0]["body"] == 'echo "hello"\necho "world"\n'

    assert instructions[1]["name"] == "RUN"
    assert len(instructions[1]["heredocs"]) == 1
    assert instructions[1]["heredocs"][0]["tag"] == "EOF"
    assert instructions[1]["heredocs"][0]["strip_indent"] is True
    assert instructions[1]["heredocs"][0]["body"] == 'echo "tabs stripped"\n'


def test_parse_dockerfile_syntax_error():
    content = "INVALID_INSTRUCTION arg"
    with pytest.raises(DockerfileSyntaxError) as exc_info:
        parse_dockerfile(content)
    assert "Unknown instruction 'INVALID_INSTRUCTION'" in str(exc_info.value)


def test_expand_vars_basic():
    env = {"FOO": "bar", "EMPTY": ""}
    assert expand_vars("hello $FOO", env) == "hello bar"
    assert expand_vars("hello ${FOO}", env) == "hello bar"
    assert expand_vars("hello \\$FOO", env) == "hello $FOO"
    assert expand_vars("hello $UNKNOWN", env) == "hello "
    assert expand_vars("hello ${UNKNOWN}", env) == "hello "


def test_expand_vars_modifiers():
    env = {"SET": "value", "EMPTY": "", "UNSET": None}

    # :- (set and non-empty)
    assert expand_vars("${SET:-default}", env) == "value"
    assert expand_vars("${EMPTY:-default}", env) == "default"
    assert expand_vars("${UNSET:-default}", env) == "default"

    # - (set, could be empty)
    assert expand_vars("${SET-default}", env) == "value"
    assert expand_vars("${EMPTY-default}", env) == ""
    assert expand_vars("${UNSET-default}", env) == "default"

    # :+ (set and non-empty -> alternate value)
    assert expand_vars("${SET:+alternate}", env) == "alternate"
    assert expand_vars("${EMPTY:+alternate}", env) == ""
    assert expand_vars("${UNSET:+alternate}", env) == ""

    # + (set -> alternate value)
    assert expand_vars("${SET+alternate}", env) == "alternate"
    assert expand_vars("${EMPTY+alternate}", env) == "alternate"
    assert expand_vars("${UNSET+alternate}", env) == ""


def test_expand_vars_errors():
    with pytest.raises(DockerfileSyntaxError) as exc_info:
        expand_vars("hello ${UNCLOSED", {})
    assert "Unterminated ${...}" in str(exc_info.value)
