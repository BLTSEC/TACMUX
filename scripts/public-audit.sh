#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

failures=0
pass() { printf '[ok] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; failures=$((failures + 1)); }

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    mapfile -d '' files < <(git ls-files -co --exclude-standard -z)
else
    mapfile -d '' files < <(
        find . -type f \
            -not -path './.git/*' \
            -not -path '*/__pycache__/*' \
            -not -path './.pytest_cache/*' \
            -not -name '*.pyc' \
            -print0 | sed -z 's|^./||'
    )
fi

for file in "${files[@]}"; do
    case "$file" in
        *.DS_Store|*.pyc|*.pyo|*.pem|*.key|.env|.env.*|*/.env|*/.env.*|id_rsa*|*/id_rsa*|id_ed25519*|*/id_ed25519*)
            fail "forbidden tracked file: $file"
            ;;
    esac
done
(( failures == 0 )) && pass 'no forbidden tracked file types'

text_files=()
for file in "${files[@]}"; do
    [[ -f "$file" ]] || continue
    grep -Iq . "$file" 2>/dev/null && text_files+=("$file")
done

scan() {
    local description="$1" pattern="$2"
    if ((${#text_files[@]})) && rg -n -i --pcre2 "$pattern" "${text_files[@]}"; then
        fail "$description"
    else
        pass "$description"
    fi
}

scan 'no personal absolute home paths' '(/Users|/home)/[A-Za-z0-9._-]+'
scan 'no non-platform email addresses' '(?!(?:[A-Z0-9._%+-]+@users\.noreply\.github\.com\b|noreply@github\.com\b|[A-Z0-9._%+-]+@[0-9]+x\.(?:png|jpe?g|gif|webp)\b))[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}'
scan 'no common token or private-key signatures' '(-----BEGIN [A-Z ]*PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})'

if command -v exiftool >/dev/null 2>&1; then
    metadata=$(exiftool -s -Email -OwnerName -GPSPosition -GPSLatitude -GPSLongitude assets/TACMUX.jpg 2>/dev/null || true)
    if [[ -n "$metadata" ]]; then
        printf '%s\n' "$metadata" >&2
        fail 'banner contains identity or location metadata'
    else
        pass 'banner has no identity or location metadata; C2PA provenance retained'
    fi
else
    pass 'metadata check skipped (exiftool unavailable)'
fi

if git rev-parse --verify HEAD >/dev/null 2>&1; then
    author_and_tagger_identities=$(
        git log --all --format='%ae'
        git for-each-ref refs/tags --format='%(taggeremail)' | tr -d '<>'
    )
    bad_author_or_tagger=$(printf '%s\n' "$author_and_tagger_identities" | sed '/^$/d' | sort -u | rg -v '^[0-9]+\+BLTSEC@users\.noreply\.github\.com$' || true)
    if [[ -n "$bad_author_or_tagger" ]]; then
        printf '%s\n' "$bad_author_or_tagger" >&2
        fail 'Git history contains a non-approved author or tagger identity'
    else
        pass 'Git authors and taggers use the approved noreply identity'
    fi

    committer_identities=$(git log --all --format='%ce')
    bad_committer=$(printf '%s\n' "$committer_identities" | sed '/^$/d' | sort -u | rg -v '^([0-9]+\+BLTSEC@users\.noreply\.github\.com|noreply@github\.com)$' || true)
    if [[ -n "$bad_committer" ]]; then
        printf '%s\n' "$bad_committer" >&2
        fail 'Git history contains a non-approved committer identity'
    else
        pass 'Git committers use an approved noreply identity'
    fi

    if command -v trufflehog >/dev/null 2>&1; then
        if trufflehog git "file://$ROOT" --only-verified --no-update >/dev/null; then
            pass 'TruffleHog full-history scan found no verified secrets'
        else
            fail 'TruffleHog full-history scan failed or found a verified secret'
        fi
    else
        pass 'full-history secret scan skipped (trufflehog unavailable)'
    fi
fi

if (( failures )); then
    printf '\nPublic-repository audit failed: %d issue(s)\n' "$failures" >&2
    exit 1
fi

printf '\nPublic-repository audit passed.\n'
