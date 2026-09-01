# Cockpit tour

`assets/tacmux-v2-tour.gif` and `assets/tacmux-v2-targets.png` are generated, not
hand-captured. Both are rebuilt by one script.

## Rebuild

Install [VHS](https://github.com/charmbracelet/vhs) and FFmpeg, put `tacmux` on
`PATH`, then run from the repository root:

```bash
scripts/render-demo.sh
```

## What it does

`setup-tacmux-demo.py` builds an isolated temporary workspace under
`/tmp/tacmux-vhs-demo` from `tests/fixtures/external_internal_example.json`, the
public synthetic Northstar engagement. It refuses to run unless that directory
is absent, and it never reads a configured workspace, so a real engagement
cannot reach the recording.

`tacmux-v2.tape` then drives the cockpit through the five views and the command
palette. The renderer converts the capture to a GIF, extracts the first settled
Targets frame as the still, and fails if the GIF exceeds 10 MiB. The temporary
workspace is removed on exit.

Both artifacts are required at release time; `scripts/release-preflight.py`
fails if either is missing or unreferenced.
