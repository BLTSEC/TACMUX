from __future__ import annotations

from dataclasses import replace
import os
import stat
import subprocess

import pytest

from tacmux.errors import ConflictError, ExternalToolError
from tacmux.migration import import_v1_workspace
from tacmux.model import AssessmentType, ScopeGroup, TargetAddress
from tacmux.nocap import NocapReader
from tacmux.tmux import TmuxService


class FakeTmux(TmuxService):
    def __init__(self, settings):
        super().__init__(settings, binary="tmux")
        self.sessions: set[str] = set()
        self.calls: list[list[str]] = []

    def available(self) -> bool:
        return True

    def has_session(self, session_name: str) -> bool:
        return session_name in self.sessions

    def run(self, args, **kwargs):
        args = list(args)
        self.calls.append(args)
        if args[0] == "new-session":
            self.sessions.add(args[args.index("-s") + 1])
            return subprocess.CompletedProcess(args, 0, "%1\n", "")
        if args[0] == "kill-session":
            target = args[args.index("-t") + 1].removeprefix("=").removesuffix(":")
            self.sessions.discard(target)
        if args[0] == "display-message":
            return subprocess.CompletedProcess(args, 0, "0\n", "")
        if args[0] in {"show-environment", "show-option"}:
            return subprocess.CompletedProcess(args, 1, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")


class FailingConfigurationTmux(FakeTmux):
    def run(self, args, **kwargs):
        if args[0] == "set-option":
            raise ExternalToolError("configuration failed")
        return super().run(args, **kwargs)


def test_tmux_target_and_ops_sessions_have_stable_context(workspace, record, settings):
    scope = record.engagement.add_scope("DMZ", ScopeGroup.EXTERNAL, "198.51.100.25/32")
    target = workspace.create_target(
        record.root,
        record.engagement,
        "mail gateway",
        addresses=[TargetAddress("198.51.100.25", scope.id)],
        primary_endpoint="198.51.100.25",
    )
    record.engagement.logging_enabled = False
    workspace.save(record.root, record.engagement)
    tmux = FakeTmux(settings)
    intent = tmux.start_target(record.root, record.engagement, target)
    assert intent.session_name == f"tacmux-{record.engagement.id}-{target.id}"
    create = next(call for call in tmux.calls if call[0] == "new-session")
    assert f"TACMUX_ENGAGEMENT_ID={record.engagement.id}" in create
    assert f"TACMUX_TARGET_ID={target.id}" in create
    assert "TARGET=198.51.100.25" in create
    assert "TACMUX_NO_AUTOLOG=1" in create
    assert not any(str(item).startswith("NOCAP_WORKSPACE=") for item in create)
    assert "env -u NOCAP_WORKSPACE" in create[-1]
    assert [
        "set-environment",
        "-r",
        "-t",
        f"={intent.session_name}:",
        "NOCAP_WORKSPACE",
    ] in tmux.calls
    assert tmux.start_target(record.root, record.engagement, target) == intent

    ops = tmux.start_ops(record.root, record.engagement)
    assert ops.session_name == f"tacmux-{record.engagement.id}-ops"
    ops_create = [call for call in tmux.calls if call[0] == "new-session"][-1]
    assert "TACMUX_TARGET_NAME=" in ops_create
    assert tmux.stop_engagement_sessions(record.engagement) == 2
    with pytest.raises(ConflictError, match="not running"):
        tmux.stop_ops(record.engagement)


def test_tmux_start_cleans_partial_session_and_honors_global_logging(
    workspace, record, settings
):
    scope = record.engagement.add_scope("DMZ", ScopeGroup.EXTERNAL, "198.51.100.5/32")
    target = workspace.create_target(
        record.root,
        record.engagement,
        "gateway",
        addresses=[TargetAddress("198.51.100.5", scope.id)],
        primary_endpoint="198.51.100.5",
    )
    failing = FailingConfigurationTmux(settings)
    with pytest.raises(ExternalToolError, match="configuration failed"):
        failing.start_target(record.root, record.engagement, target)
    assert not failing.sessions

    disabled = FakeTmux(replace(settings, auto_log=False))
    disabled.start_target(record.root, record.engagement, target)
    create = next(call for call in disabled.calls if call[0] == "new-session")
    assert "TACMUX_NO_AUTOLOG=1" in create
    assert not any(call[0] == "pipe-pane" for call in disabled.calls)


def test_existing_tmux_session_context_is_refreshed(workspace, record, settings):
    scope = record.engagement.add_scope("LAN", ScopeGroup.INTERNAL, "10.60.0.0/24")
    target = workspace.create_target(
        record.root,
        record.engagement,
        "host",
        addresses=[TargetAddress("10.60.0.10", scope.id)],
        primary_endpoint="10.60.0.10",
    )
    record.engagement.logging_enabled = False
    workspace.save(record.root, record.engagement)
    tmux = FakeTmux(settings)
    tmux.start_target(record.root, record.engagement, target)
    target.addresses.append(TargetAddress("10.60.0.11", scope.id))
    target.primary_endpoint = "10.60.0.11"
    workspace.save(record.root, record.engagement)
    tmux.calls.clear()
    tmux.start_target(record.root, record.engagement, target)
    assert [
        "set-environment",
        "-t",
        f"={tmux.session_name(record.engagement, target)}:",
        "TARGET",
        "10.60.0.11",
    ] in tmux.calls


def test_nocap_workspace_is_exported_only_when_enabled(workspace, record, settings):
    scope = record.engagement.add_scope("LAN", ScopeGroup.INTERNAL, "10.61.0.0/24")
    target = workspace.create_target(
        record.root,
        record.engagement,
        "host",
        addresses=[TargetAddress("10.61.0.10", scope.id)],
        primary_endpoint="10.61.0.10",
    )
    tmux = FakeTmux(replace(settings, nocap_enabled=True, auto_log=False))
    tmux.start_target(record.root, record.engagement, target)
    create = next(call for call in tmux.calls if call[0] == "new-session")
    assert f"NOCAP_WORKSPACE={settings.workspace}" in create
    assert not any(
        call[:2] == ["set-environment", "-r"]
        and call[-1] == "NOCAP_WORKSPACE"
        for call in tmux.calls
    )


def test_nocap_adapter_is_opt_in_read_only_json(tmp_path, settings, monkeypatch):
    inherited_workspace = os.environ.get("NOCAP_WORKSPACE")
    binary = tmp_path / "cap"
    binary.write_text(
        '#!/bin/sh\nprintf \'%s\' \'{"schema_version":1,"captures":[{"id":"C1"}]}\'\n'
    )
    binary.chmod(0o700)
    disabled = NocapReader(settings, str(binary))
    with pytest.raises(ExternalToolError, match="disabled"):
        disabled.timeline("engagement/targets/host")

    enabled_settings = replace(settings, nocap_enabled=True)
    monkeypatch.setattr("tacmux.nocap.shutil.which", lambda name: str(binary))
    reader = NocapReader(enabled_settings, str(binary))
    assert reader.timeline("engagement/targets/host") == [{"id": "C1"}]
    assert os.environ.get("NOCAP_WORKSPACE") == inherited_workspace


def test_copy_only_v1_import_preserves_source(workspace, tmp_path):
    source = tmp_path / "legacy"
    target = source / "targets" / "old-mail"
    (target / "recon").mkdir(parents=True)
    (target / "recon/scan.txt").write_text("legacy evidence")
    (source / "ENGAGEMENT.md").write_text("# Legacy notes\n")
    target.chmod(0o755)
    (target / "recon/scan.txt").chmod(0o644)
    imported = import_v1_workspace(
        workspace,
        source,
        client="ACME",
        name="Imported assessment",
        assessment_type=AssessmentType.BOTH,
    )
    new_target = imported.engagement.targets[0]
    assert (source / "targets/old-mail/recon/scan.txt").read_text() == "legacy evidence"
    assert (
        imported.root / "targets" / new_target.directory / "recon/scan.txt"
    ).read_text() == "legacy evidence"
    assert (
        imported.root / "legacy-import/ENGAGEMENT.md"
    ).read_text() == "# Legacy notes\n"
    imported_target = imported.root / "targets" / new_target.directory
    assert stat.S_IMODE(imported_target.stat().st_mode) == 0o700
    assert stat.S_IMODE((imported_target / "recon/scan.txt").stat().st_mode) == 0o600
    with pytest.raises(ConflictError, match="outside"):
        import_v1_workspace(
            workspace,
            imported.root,
            client="ACME",
            name="Recursive import",
            assessment_type=AssessmentType.BOTH,
        )
