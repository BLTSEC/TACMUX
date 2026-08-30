from __future__ import annotations

from contextlib import nullcontext

from tacmux.app import TacmuxApp


class Sink:
    def __init__(self) -> None:
        self.data = bytearray()

    def write(self, value: bytes) -> None:
        self.data.extend(value)

    def close(self) -> None:
        pass


class PagerProcess:
    def __init__(self) -> None:
        self.stdin = Sink()

    def wait(self) -> int:
        return 0


def test_terminal_evidence_streams_clean_output_to_pager(
    monkeypatch, settings, workspace
):
    evidence = settings.workspace / "captured.log"
    evidence.write_bytes(b"abc\bX\nprogress 1%\rprogress 2%\n")
    app = TacmuxApp(settings)
    process = PagerProcess()
    monkeypatch.setenv("PAGER", "less -SR")
    monkeypatch.setattr("tacmux.app.shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("tacmux.app.subprocess.Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(app, "suspend", lambda: nullcontext())
    errors: list[str] = []
    monkeypatch.setattr(app, "show_error", errors.append)

    app.page_file(evidence, terminal_output=True)

    assert process.stdin.data == b"abX\nprogress 2%\n"
    assert not errors


def test_binary_evidence_is_not_sent_to_pager(monkeypatch, settings, workspace):
    evidence = settings.workspace / "capture.bin"
    evidence.write_bytes(b"before\0after")
    app = TacmuxApp(settings)
    errors: list[str] = []
    monkeypatch.setattr(app, "show_error", errors.append)

    app.page_file(evidence, terminal_output=True)

    assert errors == ["binary evidence cannot be displayed in the terminal pager"]
