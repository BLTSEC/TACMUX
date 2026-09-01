#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
raw="$repo_root/assets/.tacmux-v2-demo.raw.mp4"
gif="$repo_root/assets/tacmux-v2-tour.gif"
still="$repo_root/assets/tacmux-v2-targets.png"
palette="$(mktemp "${TMPDIR:-/tmp}/tacmux-palette.XXXXXX.png")"
demo_root="/tmp/tacmux-vhs-demo"
created_demo_root=false

cleanup() {
  rm -f -- "$raw" "$palette"
  if [[ "$created_demo_root" == true ]]; then
    rm -rf -- "$demo_root"
  fi
}
trap cleanup EXIT

for command in vhs ffmpeg tacmux python3 tmux zsh; do
  command -v "$command" >/dev/null || {
    printf 'missing required command: %s\n' "$command" >&2
    exit 1
  }
done

cd -- "$repo_root"
rm -f -- "$raw"
if [[ -e "$demo_root" ]]; then
  printf 'temporary demo root already exists; remove it after review: %s\n' \
    "$demo_root" >&2
  exit 1
fi
mkdir -m 700 -- "$demo_root"
created_demo_root=true
vhs scripts/demo/tacmux-v2.tape

filter="fps=10,scale=1200:-1:flags=lanczos"
ffmpeg -v error -y -i "$raw" -vf "$filter,palettegen=max_colors=128:stats_mode=diff" "$palette"
ffmpeg -v error -y -i "$raw" -i "$palette" \
  -lavfi "$filter [x]; [x][1:v] paletteuse=dither=bayer:bayer_scale=3:diff_mode=rectangle" \
  -map_metadata -1 -an "$gif"

# The first settled cockpit frame follows the four-second BLTSEC title card.
ffmpeg -v error -y -ss 8.5 -i "$raw" -frames:v 1 -map_metadata -1 "$still"

size="$(wc -c < "$gif" | tr -d ' ')"
if (( size >= 5000000 )); then
  printf 'demo GIF is %s bytes; expected less than 5 MB\n' "$size" >&2
  exit 1
fi
printf 'wrote %s (%s bytes)\n' "$gif" "$size"
printf 'wrote %s\n' "$still"
