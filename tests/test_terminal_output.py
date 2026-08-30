from __future__ import annotations

from io import BytesIO

from tacmux.terminal_output import iter_rendered, render_sample


def test_terminal_renderer_applies_redraw_controls():
    assert render_sample(b"progress 10%\rprogress 20%\n") == "progress 20%"
    assert render_sample(b"abc\bX") == "abX"
    assert render_sample(b"abc\x1b[2DX") == "aXc"
    assert render_sample(b"abc\x1b[2KX") == "X"


def test_terminal_renderer_streams_utf8_tabs_and_lines():
    data = "caf\u00e9\ta\n\nkept".encode()
    assert list(iter_rendered(BytesIO(data), chunk_size=2)) == [
        "caf\u00e9    a",
        "",
        "kept",
    ]
