from __future__ import annotations

import os

from tacmux.render import FULL_SCREEN_MARKER, refresh_readable, render


def test_progress_bar_collapses():
    assert render(b"10%\r50%\r100%\r\ndone\r\n") == "100%\ndone\n"


def test_line_editor_redraws_are_resolved():
    # zsh-autosuggestions style: type, back up, erase, retype.
    data = b"$ t\x08tm\x1b[K\x1b[2Dtm log x\x1b[K\r\n"
    assert render(data) == "$ tm log x\n"


def test_colours_titles_and_cursor_moves():
    data = b"\x1b]0;title\x07\x1b[31mred\x1b[0m\x1b[3Gd!\r\n"
    assert render(data) == "red!\n"


def test_full_screen_programs_become_a_marker():
    data = b"before\r\n\x1b[?1049hvim screen\x1b[2J\x1b[?1049lafter\r\n"
    assert render(data) == f"before\n{FULL_SCREEN_MARKER}\nafter\n"


def test_bare_lf_starts_a_new_line_and_split_utf8_is_safe():
    assert render(b"a\nb\n") == "a\nb\n"
    assert render("é".encode()[:1] + b"\r\n") == "�\n"


def test_blank_runs_collapse():
    assert render(b"a\r\n\r\n\r\n\r\n\r\nb\r\n") == "a\n\n\nb\n"


def _raw(root, name, target, body: bytes):
    day = root / "logs/20260101"
    day.mkdir(parents=True, exist_ok=True)
    path = day / name
    path.write_bytes(f"=== TACMUX pane log ===\nTarget: {target}\n\n".encode() + body)
    return path


def test_refresh_readable_is_incremental_and_filtered(tmp_path):
    raw = _raw(tmp_path, "A_p1.log", "WEB", b"one\r\n")
    ops = _raw(tmp_path, "O_p1.log", "ENGAGEMENT", b"ops\r\n")
    _raw(tmp_path, "scrollback_A.log", "WEB", b"exact\r\n")
    assert refresh_readable(tmp_path, "WEB") == [raw.with_suffix(".txt")]
    assert raw.with_suffix(".txt").stat().st_mode & 0o777 == 0o600
    assert refresh_readable(tmp_path, "WEB") == []  # fresh
    with raw.open("ab") as stream:
        stream.write(b"two\r\n")
    future = raw.with_suffix(".txt").stat().st_mtime_ns + 10**9
    os.utime(raw, ns=(future, future))
    assert refresh_readable(tmp_path, "WEB") == [raw.with_suffix(".txt")]
    assert "two" in raw.with_suffix(".txt").read_text()
    assert refresh_readable(tmp_path, "") == [ops.with_suffix(".txt")]
    assert not (tmp_path / "logs/20260101/scrollback_A.txt").exists()


def test_refresh_readable_refuses_linked_output(tmp_path, capsys):
    raw = _raw(tmp_path, "A_p1.log", "WEB", b"x\r\n")
    raw.with_suffix(".txt").symlink_to(tmp_path / "elsewhere")
    assert refresh_readable(tmp_path) == []
    assert "refusing linked" in capsys.readouterr().err


def test_colon_parameters_unterminated_osc_and_esc_newline():
    assert render(b"\x1b[38:5:196mred\x1b[0m\r\n") == "red\n"
    assert render(b"\x1b]0;broken title\nafter\r\n") == "\nafter\n"
    assert render(b"a\x1b\nb\r\n") == "a\nb\n"


def test_streaming_matches_whole_render(monkeypatch):
    import tacmux.render as module

    data = (b"scan 1%\rscan 99%\r\n\x1b[31mred\x1b[0m\r\n" + "é".encode()) * 50
    expected = render(data)
    monkeypatch.setattr(module, "CHUNK", 7)
    assert render(data) == expected


def test_long_lines_wrap_to_bound_memory(monkeypatch):
    import tacmux.render as module

    monkeypatch.setattr(module, "LINE_LIMIT", 10)
    assert render(b"x" * 25 + b"\r\n") == "xxxxxxxxxx\nxxxxxxxxxx\nxxxxx\n"


def test_readable_copy_takes_the_raw_mtime(tmp_path):
    raw = _raw(tmp_path, "A_p1.log", "WEB", b"one\r\n")
    refresh_readable(tmp_path)
    assert raw.with_suffix(".txt").stat().st_mtime_ns == raw.stat().st_mtime_ns
