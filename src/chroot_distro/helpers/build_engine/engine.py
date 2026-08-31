# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Drive a parsed Dockerfile: one stage per FROM, one handler per instruction.

The engine keeps only what crosses a stage boundary, the global ARG scope, the
named-stage map `COPY --from=` resolves against, and which stage is current;
everything else a step does it does to the stage or to the rootfs on disk.

A prescan runs first, and `plan_stages` is what it runs: one walk that resolves
every FROM's platform and collects the global ARG scope, so a `--target` naming
no stage, a FROM that does not parse and a `--platform` that does not resolve all
fail before anything is pulled. `build` calls the same function for its emulator
preflight, which is why the resolution lives in a function rather than in the
walk. FROM is then the one instruction the engine handles itself: it makes the
stage's scratch tree off this run's scratch-root descriptor, takes the config
from `scratch`, from an earlier stage or from a pulled image, seeds env, workdir,
user and shell out of it, writes the stage's resolv.conf and hosts so a RUN can
resolve a name, and fires the base image's ONBUILD triggers. Global ARGs start
unset in a new stage and become visible again only when a bare `ARG NAME`
re-declares one, which is Docker's rule and not an omission; the automatic
TARGET*/BUILD* values follow that rule too, so `platform_args` is what a bare
`ARG TARGETARCH` reads and `expansion_scope` does not carry them.

`_adopt_image_config` is this module's trust boundary, and its own docstring is
where the reasoning lives: a pulled config is a document this program did not
write, every field of it is read back by a handler, so it is held to the type OCI
says it is at the single point it is adopted.

`firing_onbuild` is true only while a base image's triggers run, which is what
lets `do_env` tell a stranger's ENV line from the Dockerfile author's. An ONBUILD
in this Dockerfile records a trigger for whoever builds FROM the result and fires
nothing here. A trigger fires once and is then dropped from the stage's config,
which is where BuildKit clears one too: it belongs to the image or stage this one
stands on, so the image this build publishes must not re-announce it and a stage
built FROM this one must not fire it a second time.

Every instruction appends one history entry, with `created` pinned to the epoch
so a rebuild produces the same config and `empty_layer` set when the handler grew
no layer. The count of non-empty entries has to equal len(rootfs.diff_ids) or a
registry renders the image's layers wrong, so the entry is written by the call
that ran the handler rather than by each handler.
"""

import dataclasses
import json
import logging
import os
import re
import time
import typing

from chroot_distro import dirfd
from chroot_distro.arch import Platform, get_device_platform, parse_platform, platform_from_arch
from chroot_distro.helpers.build_engine.constants import (
    EXPANDS_VARS,
    PREDEFINED_ARGS,
    is_host_exec_var,
    needs_chroot,
)
from chroot_distro.helpers.build_engine.dockerignore import load_dockerignore
from chroot_distro.helpers.build_engine.errors import BuildError
from chroot_distro.helpers.build_engine.events import (
    BuildEvent,
    NullReporter,
    PlainReporter,
    Reporter,
)
from chroot_distro.helpers.build_engine.handlers import HANDLERS, do_onbuild
from chroot_distro.helpers.build_engine.parsing import split_arg
from chroot_distro.helpers.build_engine.stage import Stage
from chroot_distro.helpers.docker import (
    apply_layer,
    layer_cache_path,
    pull_image,
)
from chroot_distro.helpers.dockerfile import DockerfileSyntaxError, expand_vars, parse_dockerfile
from chroot_distro.helpers.rootfs import write_hosts, write_resolv_conf
from chroot_distro.message import log_info

log = logging.getLogger(__name__)

_FROM_RE = re.compile(r"^\s*(\S+)(?:\s+AS\s+(\S+))?\s*$", re.IGNORECASE)


@dataclasses.dataclass
class StagePlan:
    """What one FROM decides before anything is pulled.

    `runs` is whether the stage carries an instruction that execs a guest
    binary, which is what decides whether its platform needs an emulator.
    """

    name: str
    platform: Platform
    runs: bool = False


def _platform_args(target: Platform, build: Platform) -> dict[str, str]:
    """The automatic TARGET*/BUILD* ARG values, which Docker keeps global."""
    return {
        "TARGETPLATFORM": target.format(),
        "TARGETOS": target.os,
        "TARGETARCH": target.architecture,
        "TARGETVARIANT": target.variant,
        "BUILDPLATFORM": build.format(),
        "BUILDOS": build.os,
        "BUILDARCH": build.architecture,
        "BUILDVARIANT": build.variant,
    }


def _from_scope(global_args: dict[str, str], target: Platform, build: Platform) -> dict[str, str | None]:
    """The scope a FROM line is expanded against: global ARGs, then the platform values."""
    scope: dict[str, str | None] = dict(global_args)
    for key, value in _platform_args(target, build).items():
        scope.setdefault(key, value)
    return scope


def _from_parts(value: str, lineno: int) -> tuple[str, str]:
    """Split an expanded FROM value into (base reference, stage name)."""
    m = _FROM_RE.match(value)
    if not m:
        raise BuildError(f"Invalid FROM at line {lineno}: {value!r}")
    return m.group(1), m.group(2) or ""


def _from_platform(raw: typing.Any, scope: dict[str, str | None], default: Platform, lineno: int) -> Platform:
    """Resolve one FROM's `--platform`, or return *default* when it carries none."""
    if raw is None:
        return default
    if not isinstance(raw, str) or not raw.strip():
        raise BuildError(f"FROM --platform needs a value (line {lineno}).")
    value = expand_vars(raw, scope).strip()
    if not value:
        raise BuildError(f"FROM --platform={raw} expanded to nothing (line {lineno}).")
    try:
        return parse_platform(value)
    except ValueError as exc:
        raise BuildError(f"FROM --platform={value}: {exc} (line {lineno}).") from exc


def plan_stages(
    instructions: list[dict[str, typing.Any]],
    *,
    target_platform: Platform,
    build_platform: Platform,
    user_build_args: dict[str, str],
) -> tuple[list[StagePlan], dict[str, str]]:
    """One walk of the instructions: a plan per FROM, and the global ARG scope.

    The one place a stage's platform is decided, so `build`'s emulator preflight
    and the engine cannot disagree about what a stage is built for. Nothing here
    opens or fetches anything, which is the point: a Dockerfile whose FROM lines
    do not resolve is refused before the first pull.

    A bare FROM takes the target platform, and `--platform` is expanded against
    the scope a FROM sees, so `--platform=$BUILDPLATFORM` reaches the build
    platform. A FROM naming an earlier stage takes that stage's platform
    whatever the flag says, because the tree it starts from is that stage's;
    Docker resolves one the same way.
    """
    plans: list[StagePlan] = []
    by_name: dict[str, Platform] = {}
    global_args: dict[str, str] = {}
    seen_from = False

    for instr in instructions:
        name = instr.get("name", "")
        lineno = instr.get("lineno", 0)
        flags = instr.get("flags") or {}

        if name != "FROM":
            if "platform" in flags:
                raise BuildError(f"{name} --platform is not supported (line {lineno}); only FROM takes one.")
            if name == "ARG" and not seen_from:
                key, default = split_arg(instr["value"])
                if key:
                    global_args[key] = user_build_args.get(key, default or "")
            elif plans and needs_chroot([instr]):
                plans[-1].runs = True
            continue

        seen_from = True
        for key in flags:
            if key != "platform":
                raise BuildError(f"FROM --{key} is not supported (line {lineno}); refusing to silently ignore it.")

        scope = _from_scope(global_args, target_platform, build_platform)
        value = instr["value"] if isinstance(instr["value"], str) else ""
        base_ref, stage_name = _from_parts(expand_vars(value, scope), lineno)
        platform = _from_platform(flags.get("platform"), scope, target_platform, lineno)
        if base_ref in by_name:
            platform = by_name[base_ref]
        plans.append(StagePlan(name=stage_name, platform=platform))
        # `COPY --from=0` and `FROM 0` reach a stage by index, so the engine
        # registers both names and the plan has to know both as well.
        by_name[str(len(plans) - 1)] = platform
        if stage_name:
            by_name[stage_name] = platform

    return plans, global_args


def _malformed(image_ref: str, what: str) -> typing.NoReturn:
    """The one refusal shape for a base image config that will not do."""
    raise BuildError(f"FROM {image_ref}: the image config is malformed: {what}.")


def _cfg_object(value: typing.Any, image_ref: str, what: str) -> dict[str, typing.Any]:
    if not isinstance(value, dict):
        _malformed(image_ref, f"{what} is not an object")
    return value


def _cfg_str_list(value: typing.Any, image_ref: str, what: str) -> list[str]:
    if not isinstance(value, list):
        _malformed(image_ref, f"{what} is not a list")
    for entry in value:
        if not isinstance(entry, str):
            _malformed(image_ref, f"{what} holds an entry that is not a string")
    return value


def _adopt_image_config(image_config: typing.Any, image_ref: str) -> dict[str, typing.Any]:
    """Return a pulled image's config, held to the shapes read out of it.

    Two things happen here, both at the point a stranger's config is *adopted*
    rather than where it is used, so nothing downstream can re-seed a value: a
    stage's env is seeded from this at FROM, `FROM <earlier stage>` deep-copies
    the whole config, and what the build finally stores as its own image's
    config comes from here too. One pass, and all three are clean by
    construction.

    The first is the LD_* filter over `Env`. An ENV line in the user's own
    Dockerfile still reaches the image config: it goes through do_env, which
    writes this same list afterwards, and what a Dockerfile says about the
    image it produces is its author's business. What no such name reaches from
    any source is the environment a RUN step is exec'd with, which run_step
    refuses separately (constants.is_host_exec_var states the one rule both
    apply).

    The second is the shape. Every field below is read back by this module or
    by a handler: `User` and `Shell` decide what a RUN step runs and who as,
    `WorkingDir` becomes its cwd, `OnBuild` is parsed as Dockerfile lines,
    `Env` seeds the stage, `Cmd` and `Entrypoint` are what `run` later
    executes, `Labels`, `ExposedPorts` and `Volumes` are merged into by their
    handlers, and `history` is appended to once per instruction. All of it is a
    registry's JSON, or a manifest-cache entry's, which on Termux sits under
    the bound $TERMUX_PREFIX and is a guest's to compose. Every consumer
    subscripted it as the type OCI says it is: `"config": "x"` was an
    AttributeError at FROM, `"Labels": ["a"]` a ValueError in do_label,
    `"OnBuild": 5` a TypeError, `"history": null` an AttributeError at the
    first instruction, and `build` catches none of those, so each was a
    traceback rather than a message.

    A field of the wrong type is a refusal naming it, not a value dropped
    quietly: two of them decide what runs, and the rest would otherwise be
    carried into the image this build publishes and hands to whoever pulls it.
    Absent and JSON `null` are simply "not set", which is how a registry spells
    an empty field; a `null` is removed rather than left standing, since
    `.get(key) or default` and `setdefault(key, default)` do not answer alike
    for one.
    """
    doc = _cfg_object(image_config, image_ref, "the document")

    if doc.get("history") is None:
        doc.pop("history", None)
    elif not isinstance(doc["history"], list):
        _malformed(image_ref, "'history' is not a list")

    if doc.get("rootfs") is None:
        doc.pop("rootfs", None)
    else:
        rootfs = _cfg_object(doc["rootfs"], image_ref, "'rootfs'")
        if rootfs.get("diff_ids") is None:
            rootfs.pop("diff_ids", None)
        else:
            _cfg_str_list(rootfs["diff_ids"], image_ref, "'rootfs.diff_ids'")

    if doc.get("config") is None:
        doc["config"] = {}
        return doc
    cfg = _cfg_object(doc["config"], image_ref, "'config'")

    for key in ("Cmd", "Entrypoint", "OnBuild", "Shell"):
        if cfg.get(key) is None:
            cfg.pop(key, None)
        else:
            _cfg_str_list(cfg[key], image_ref, f"'config.{key}'")

    for key in ("User", "WorkingDir"):
        if cfg.get(key) is None:
            cfg.pop(key, None)
        elif not isinstance(cfg[key], str):
            _malformed(image_ref, f"'config.{key}' is not a string")

    for key in ("ExposedPorts", "Volumes"):
        if cfg.get(key) is None:
            cfg.pop(key, None)
        else:
            # The key set is the whole of what either field says: the spec's
            # value is an empty object, and both handlers write one. Rewritten
            # rather than checked, so an inherited value of any other shape
            # cannot reach the built image either.
            names = _cfg_object(cfg[key], image_ref, f"'config.{key}'")
            cfg[key] = {name: {} for name in names}

    if cfg.get("Labels") is None:
        cfg.pop("Labels", None)
    else:
        labels = _cfg_object(cfg["Labels"], image_ref, "'config.Labels'")
        for value in labels.values():
            if value is not None and not isinstance(value, str):
                _malformed(image_ref, "'config.Labels' holds a value that is not a string")
        # A null label value is the empty string, as it is to every other
        # reader of a map of strings.
        cfg["Labels"] = {k: (v if v is not None else "") for k, v in labels.items()}

    if cfg.get("Env") is None:
        cfg.pop("Env", None)
    else:
        env_list = _cfg_str_list(cfg["Env"], image_ref, "'config.Env'")
        cfg["Env"] = [e for e in env_list if not ("=" in e and is_host_exec_var(e.partition("=")[0]))]

    return doc


def _stage_rootfs_fd(stage: Stage) -> int:
    """A caller-owned descriptor on *stage*'s rootfs.

    Re-opened from the stage's pin when it has one, so the tree that is
    written is the one the stage was created against and not whatever the
    name resolves to now; opened by name only for a stage some caller
    (a test) built itself.
    """
    if stage.rootfs_fd is not None:
        return dirfd.reopen(stage.rootfs_fd)
    return dirfd.opendir(stage.rootfs_dir)


class BuildEngine:
    """Walks a parsed Dockerfile and produces an OCI image in-place.

    The engine owns the cross-stage state (the global ARG scope, the
    map of named stages so COPY --from= can resolve them, the current
    Stage). Each instruction is dispatched to a handler module
    (handlers.py / copy_step.py / run_step.py) that mutates either
    the engine, the current stage, or the rootfs on disk.
    """

    def __init__(
        self,
        build_dir: str,
        tmp_root: str,
        target_arch_pd: str,
        user_build_args: dict[str, str],
        target_stage: str | None,
        verbose: bool,
        quiet: bool,
        no_cache: bool,
        emulator: str | None,
        isolation_mode: str = "none",
        secrets: dict[str, str] | None = None,
        ssh_sockets: dict[str, str] | None = None,
        reporter: Reporter | None = None,
        tmp_root_fd: int | None = None,
        target_platform: Platform | None = None,
        build_platform: Platform | None = None,
    ):
        self.build_dir = os.path.abspath(build_dir)
        self.tmp_root = tmp_root
        # Descriptor on this run's own scratch root. Every stage tree is made
        # off it, so the stage descriptors name inodes below the directory the
        # build created rather than below whatever `tmp_root` resolves to by
        # the time a stage starts. None only for a caller that made the tree.
        self.tmp_root_fd = tmp_root_fd
        self.target_platform = target_platform or platform_from_arch(target_arch_pd)
        self.build_platform = build_platform or get_device_platform()
        self.target_arch_pd = self.target_platform.to_arch()
        self.target_arch_docker = self.target_platform.architecture
        self.host_arch_docker = self.build_platform.architecture
        self.user_build_args = dict(user_build_args)
        self.target_stage = target_stage
        self.verbose = verbose
        self.quiet = quiet
        self.no_cache = no_cache
        self.emulator = emulator
        # How RUN steps are separated from the host: "none" (plain chroot),
        # "ns" (namespaces + default mount set, CD_USE_NS), or "max"
        # (maximum-isolation chrooted holder, CD_USE_ISOLATION).
        if isolation_mode not in ("none", "ns", "max"):
            raise ValueError(f"unknown isolation_mode {isolation_mode!r}")
        self.isolation_mode = isolation_mode
        # CLI-provided RUN --mount inputs: secret id -> host file path,
        # ssh id -> agent socket path.
        self.secrets = dict(secrets or {})
        self.ssh_sockets = dict(ssh_sockets or {})
        self.reporter: Reporter = reporter or (NullReporter() if quiet else PlainReporter())
        self.stages: dict[str, Stage] = {}
        self.stages_by_idx: list[Stage] = []
        self.current: Stage | None = None
        # One entry per FROM, filled by the prescan: what a stage is built for
        # is settled there and read back here rather than resolved twice.
        self.stage_plans: list[StagePlan] = []
        self.global_args: dict[str, str] = {}
        self.declared_global: set[str] = set()
        self.ignore_patterns = load_dockerignore(self.build_dir)
        # LD_* names the Dockerfile set and the host-side chroot exec was
        # refused (run_step._refuse_host_exec). Kept per build so a name is
        # named once rather than once per RUN step.
        self.warned_host_exec: set[str] = set()
        # True only while the base image's ONBUILD triggers run, so do_env can
        # tell a stranger's ENV line from the author's.
        self.firing_onbuild = False
        self._stop_after = False
        self._step_no = 0
        self._step_total = 0

    def run(self, instructions: list[dict[str, typing.Any]]) -> Stage:
        """Walk the instruction list and return the chosen stage."""
        self._prescan(instructions)

        self._step_total = len(instructions)
        for instr in instructions:
            self._step_no += 1
            self._announce(instr)
            t0 = time.monotonic()
            self._dispatch(instr)
            self.reporter.emit(self._event("step_finished", instr, duration=time.monotonic() - t0))
            if self._stop_after:
                break

        if self.current is None:
            raise BuildError("Dockerfile contains no FROM instruction.")

        return self._target()

    def close(self) -> None:
        """Release every stage's descriptors. Idempotent."""
        for stage in self.stages_by_idx:
            stage.close()

    def _prescan(self, instructions: list[dict[str, typing.Any]]) -> None:
        self.stage_plans, self.global_args = plan_stages(
            instructions,
            target_platform=self.target_platform,
            build_platform=self.build_platform,
            user_build_args=self.user_build_args,
        )
        self.declared_global = set(self.global_args)
        named_stages = [plan.name for plan in self.stage_plans if plan.name]

        if self.target_stage and self.target_stage not in named_stages:
            raise BuildError(
                f"--target stage '{self.target_stage}' is not defined in "
                f"the Dockerfile (known stages: "
                f"{', '.join(named_stages) or 'none'})."
            )

    def _expand_for_from(self, value: str) -> str:
        """Expand variables for a FROM line using global ARGs only."""
        return expand_vars(value, _from_scope(self.global_args, self.target_platform, self.build_platform))

    def platform_args(self) -> dict[str, str]:
        """The automatic TARGET*/BUILD* values a bare `ARG NAME` re-exposes in a stage."""
        return _platform_args(self.target_platform, self.build_platform)

    def _stage_label(self) -> str:
        if self.current is None:
            return ""
        return self.current.name or str(self.current.index)

    def _event(
        self,
        kind: str,
        instr: dict[str, typing.Any],
        *,
        text: str = "",
        duration: float | None = None,
    ) -> BuildEvent:
        return BuildEvent(
            kind=kind,
            step_no=self._step_no,
            step_total=self._step_total,
            stage_name=self._stage_label(),
            instruction=instr.get("name", ""),
            text=text,
            duration=duration,
            lineno=instr.get("lineno", 0),
        )

    def _announce(self, instr: dict[str, typing.Any]) -> None:
        self.reporter.emit(self._event("step_started", instr, text=instr.get("raw", "")))

    def report_cache_hit(self, instr: dict[str, typing.Any]) -> None:
        """Emit a cache_hit event for *instr* (called by the RUN handler)."""
        self.reporter.emit(self._event("cache_hit", instr))

    def log(self, text: str) -> None:
        """Emit *text* as a log_line event (rendered via log_info by default)."""
        self.reporter.emit(BuildEvent(kind="log_line", text=text))

    def _dispatch(self, instr: dict[str, typing.Any]) -> None:
        name = instr["name"]
        if name == "FROM":
            self._do_from(instr)
            return
        if self.current is None:
            if name == "ARG":
                return
            raise BuildError(f"Instruction '{name}' before any FROM at line {instr['lineno']}.")
        if name == "ONBUILD":
            do_onbuild(self, instr)
            self._record_history(instr, layer_added=False)
            return
        if name in EXPANDS_VARS and not instr["exec_form"]:
            instr = self._expand_instruction(instr)

        handler = HANDLERS.get(name)
        if handler is None:
            raise BuildError(f"Unsupported instruction '{name}' at line {instr['lineno']}.")
        self._run_with_history(handler, instr)

    def _run_with_history(
        self, handler: typing.Callable[[typing.Any, dict[str, typing.Any]], None], instr: dict[str, typing.Any]
    ) -> None:
        """Run handler, then append a history entry for the instruction.

        Whether the entry is marked empty_layer depends on whether the
        handler grew `stage.layers`. The OCI image-config spec requires
        the count of non-empty-layer history entries to equal
        len(rootfs.diff_ids); registries (notably Docker Hub) render
        this array in their "Image Layers" UI, so an out-of-date
        history makes built layers invisible.
        """
        assert self.current is not None
        layers_before = len(self.current.layers)
        handler(self, instr)
        layer_added = len(self.current.layers) > layers_before
        self._record_history(instr, layer_added=layer_added)

    def _record_history(self, instr: dict[str, typing.Any], layer_added: bool) -> None:
        """Append one entry to image_config["history"] for `instr`.

        `created_by` is the raw Dockerfile line (what Docker Hub
        displays under each step); `created` is fixed to the epoch so
        the image config is reproducible across builds. Entries that
        did not produce a filesystem layer carry empty_layer=true, so
        the count of non-empty entries always equals len(diff_ids).
        """
        assert self.current is not None
        entry: dict[str, typing.Any] = {
            "created": "1970-01-01T00:00:00Z",
            "created_by": instr.get("raw") or instr["name"],
        }
        if not layer_added:
            entry["empty_layer"] = True
        cfg = self.current.image_config
        cfg.setdefault("history", []).append(entry)

    def _expand_instruction(self, instr: dict[str, typing.Any]) -> dict[str, typing.Any]:
        """Return a copy of instr with its `value` variable-expanded."""
        env = self.expansion_scope()
        new = dict(instr)
        value = instr.get("value", "")
        if isinstance(value, str):
            new["value"] = expand_vars(value, env)

        def _expand_flag(v: typing.Any) -> typing.Any:
            if isinstance(v, str):
                return expand_vars(v, env)
            if isinstance(v, list):
                return [expand_vars(x, env) if isinstance(x, str) else x for x in v]
            return v

        new["flags"] = {k: _expand_flag(v) for k, v in instr.get("flags", {}).items()}
        return new

    def expansion_scope(self) -> dict[str, str | None]:
        """Variable scope for `${VAR}` expansion inside the current stage.

        Composed in increasing precedence: PREDEFINED_ARGS from the host
        env, declared ARGs in this stage, and finally ENVs (which win
        over ARGs by Docker semantics). The automatic platform values are
        deliberately absent: they live in the global scope, and a bare
        `ARG TARGETARCH` is what brings one into a stage (handlers.do_arg).
        """
        assert self.current is not None
        scope: dict[str, str | None] = {}
        for k in PREDEFINED_ARGS:
            v = os.environ.get(k, "")
            if v:
                scope[k] = v
        for k, v in self.current.args.items():
            scope[k] = v
        for k, v in self.current.env.items():
            scope[k] = v
        return scope

    def _do_from(self, instr: dict[str, typing.Any]) -> None:
        # The FROM after the --target stage ends this invocation.
        if self.target_stage and self.current is not None and self.current.name == self.target_stage:
            self._stop_after = True
            return

        value = self._expand_for_from(
            instr["value"] if isinstance(instr["value"], str) else "",
        )
        base_ref, stage_name = _from_parts(value, instr["lineno"])

        idx = len(self.stages_by_idx)
        # Every FROM before this one made a stage, so the prescan's plans and
        # the stage list are indexed alike.
        stage_platform = self.stage_plans[idx].platform
        rootfs_dir = os.path.join(self.tmp_root, f"stage-{idx}", "rootfs")
        stage_fd, rootfs_fd = self._make_stage_dirs(idx)
        stage = Stage(
            index=idx,
            name=stage_name,
            rootfs_dir=rootfs_dir,
            target_arch_pd=stage_platform.to_arch(),
            platform=stage_platform,
            dir_fd=stage_fd,
            rootfs_fd=rootfs_fd,
        )

        # The stage is not registered yet, so close() would not reach it.
        try:
            if base_ref.lower() == "scratch":
                stage.image_config = {"config": {}}
            elif base_ref in self.stages:
                self._inherit_from_stage(stage, self.stages[base_ref])
            else:
                self._pull_base_image(stage, base_ref)
        except BaseException:
            stage.close()
            raise

        cfg = stage.image_config.get("config") or {}
        env_list = cfg.get("Env") or []
        for entry in env_list:
            if isinstance(entry, str) and "=" in entry:
                k, _, v = entry.partition("=")
                stage.env[k] = v
        if cfg.get("WorkingDir"):
            stage.workdir = cfg["WorkingDir"] or "/"
        if cfg.get("User"):
            stage.user = cfg["User"]
        if cfg.get("Shell"):
            stage.shell = list(cfg["Shell"])

        # Re-declare global ARGs as available (no value unless declared
        # again in this stage). Docker semantics: they start unset and
        # become visible only after a bare `ARG NAME` re-declares them.
        stage.args = {}
        stage.declared_args = set()

        self.stages_by_idx.append(stage)
        if stage_name:
            self.stages[stage_name] = stage
        # Implicit "by index" lookup for COPY --from=0, --from=1, etc.
        self.stages[str(idx)] = stage
        self.current = stage

        # Configure DNS so RUN apt-get etc. work. Both writers open `etc`
        # off the stage descriptor and skip the fixup when there is none, so
        # no separate isdir() probe (which would name the rootfs again).
        try:
            write_resolv_conf(rootfs_dir, root_fd=stage.rootfs_fd)
            write_hosts(rootfs_dir, root_fd=stage.rootfs_fd)
        except OSError as exc:
            log.warning("Failed to configure DNS for build stage: %s", exc)

        base_onbuild = (stage.image_config.get("config") or {}).get("OnBuild") or []
        if base_onbuild:
            self._fire_base_onbuild(stage, base_ref)

    def _fire_base_onbuild(self, stage: Stage, base_ref: str) -> None:
        """Run the triggers *stage*'s base recorded, then drop them.

        A trigger that fires is always the base's, never this Dockerfile's: an
        ONBUILD here only records one for whoever builds FROM the result. So an
        ENV among them is a stranger's line, and do_env holds it to the rule the
        image's own Env is held to.

        They are cleared from this stage's config before the first one runs,
        which is where BuildKit clears them: the triggers answer for the image
        or stage this one was built from, so the image this build publishes must
        not re-announce them and a `FROM <this stage>` must not fire them again.

        The text is a Dockerfile line out of a config this program did not write,
        so a trigger that does not parse names the base rather than ending the
        build in a traceback: `build` catches BuildError and OSError, and a
        DockerfileSyntaxError is neither.
        """
        cfg = stage.image_config.setdefault("config", {})
        triggers = list(cfg.pop("OnBuild", None) or [])
        self.firing_onbuild = True
        try:
            for trig in triggers:
                try:
                    _, trig_instrs = parse_dockerfile(trig + "\n")
                except DockerfileSyntaxError as exc:
                    raise BuildError(f"FROM {base_ref}: ONBUILD trigger {trig!r} does not parse: {exc}") from exc
                for ti in trig_instrs:
                    self._step_no += 1
                    self._announce(ti)
                    trig_instr = ti
                    if ti["name"] in EXPANDS_VARS and not ti["exec_form"]:
                        trig_instr = self._expand_instruction(ti)
                    h = HANDLERS.get(trig_instr["name"])
                    if h is None:
                        raise BuildError(
                            f"FROM {base_ref}: ONBUILD trigger uses unsupported "
                            f"instruction '{trig_instr['name']}'."
                        )
                    self._run_with_history(h, trig_instr)
        finally:
            self.firing_onbuild = False

    def _make_stage_dirs(self, idx: int) -> tuple[int | None, int | None]:
        """Create stage *idx*'s scratch tree. (stage_fd, rootfs_fd), or (None, None).

        Both levels are made with mkdirat off the run's own scratch-root
        descriptor and handed back as descriptors, so the rest of the build
        addresses the stage through the inodes created here. A caller that
        supplied the scratch root as a bare path gets the plain makedirs and
        no pin.
        """
        if self.tmp_root_fd is None:
            os.makedirs(os.path.join(self.tmp_root, f"stage-{idx}", "rootfs"), exist_ok=True)
            return None, None

        stage_fd = None
        try:
            stage_fd = dirfd.descend_at(self.tmp_root_fd, (f"stage-{idx}",), create=True)
            rootfs_fd = dirfd.descend_at(stage_fd, ("rootfs",), create=True)
        except OSError as exc:
            if stage_fd is not None:
                os.close(stage_fd)
            raise BuildError(f"cannot create the scratch tree for stage {idx}: {exc}") from exc
        return stage_fd, rootfs_fd

    def _inherit_from_stage(self, new_stage: Stage, parent: Stage) -> None:
        """Apply parent's layers to new_stage.rootfs_dir; copy config.

        The deep-copy via JSON round-trip carries the parent's
        `history` array along with the rest of image_config, so the
        new stage starts with the inherited entries and subsequent
        instructions append to the same list. The base identity comes
        along too: the tree is the parent's, so what it was pulled from
        is what this stage stands on as well.
        """
        new_stage.image_config = json.loads(json.dumps(parent.image_config))
        rootfs_fd = _stage_rootfs_fd(new_stage)
        try:
            for layer in parent.layers:
                cache_path = layer_cache_path(layer["digest"])
                if not os.path.isfile(cache_path):
                    raise BuildError(
                        f"Layer {layer['digest']} of stage '{parent.name or parent.index}' is missing from the cache."
                    )
                apply_layer(cache_path, rootfs_fd)
        finally:
            os.close(rootfs_fd)
        new_stage.layers = list(parent.layers)
        new_stage.parent_layer_digest = parent.parent_layer_digest
        new_stage.base_image_ref = parent.base_image_ref
        new_stage.base_manifest_digest = parent.base_manifest_digest

    def _pull_base_image(self, stage: Stage, image_ref: str) -> None:
        """Use helpers.docker.pull_image to populate the stage rootfs.

        The platform is the stage's own, not the build's target: a
        `FROM --platform=$BUILDPLATFORM` stage is the one that gets to run
        native while the image being built stays foreign.
        """
        log_info(f"Pulling base image '{image_ref}' ({stage.platform})...")
        try:
            rootfs_fd = _stage_rootfs_fd(stage)
        except OSError as exc:
            raise BuildError(f"FROM {image_ref}: {exc}") from exc
        try:
            meta = pull_image(image_ref, rootfs_fd, stage.platform)
        except RuntimeError as exc:
            raise BuildError(f"FROM {image_ref}: {exc}") from exc
        finally:
            os.close(rootfs_fd)

        stage.image_config = _adopt_image_config(meta.get("image_config") or {"config": {}}, image_ref)
        stage.base_image_ref = image_ref
        manifest = meta.get("manifest") or {}
        # What the pull selected for this stage, which is the base identity a
        # cache key has to carry. `_digest` is a manifest-cache field like the
        # `size` below, so a non-string is taken as absent rather than trusted.
        base_digest = manifest.get("_digest", "")
        stage.base_manifest_digest = base_digest if isinstance(base_digest, str) else ""
        config_diff_ids = (stage.image_config.get("rootfs") or {}).get("diff_ids") or []
        stage.layers = []
        for i, layer in enumerate(manifest.get("layers", [])):
            # The pull has already read every digest here, to name a blob and a
            # cache path. A `size` it never reads, and this one is copied into
            # the manifest the build publishes: take a non-int as absent, the
            # way every other reader of the field does.
            digest = layer.get("digest", "")
            size = layer.get("size", 0)
            if not isinstance(size, int) or isinstance(size, bool):
                size = 0
            diff_id = config_diff_ids[i] if i < len(config_diff_ids) else digest
            stage.layers.append({"digest": digest, "size": size, "diff_id": diff_id})
        if stage.layers:
            stage.parent_layer_digest = stage.layers[-1]["digest"]

    def _target(self) -> Stage:
        if self.target_stage:
            stage = self.stages.get(self.target_stage)
            if stage is None:
                raise BuildError(f"--target stage '{self.target_stage}' was not built.")
            return stage
        assert self.current is not None
        return self.current
