#!/usr/bin/env bash
# Zero-downtime rotation of the Anthropic API key.
#
# Why no downtime: the orchestrator is a stdio server started per Claude Code
# session. It reads the secret file at start-up. New sessions pick the new key;
# running sessions keep the old one until you close them. Both keys stay valid
# during the overlap, then you disable the old one in the Console.
#
# 1. (manual) Console > API keys > Create key "orchestrator-YYYYMMDD", then run:
#      sudo ./rotate-anthropic-key.sh            # prompts for the key, no echo
# 2. (manual) Restart Claude Code sessions, check the audit log shows the new fingerprint.
# 3. (manual) Console > disable the old key. Wait 24 h, then delete it.
set -euo pipefail
SECRET=${SECRET:-/etc/claude-orchestrator/secrets/anthropic_api_key}
UID_ORCH=${UID_ORCH:-10001}

read -r -s -p "New Anthropic API key: " NEW; echo
[[ "$NEW" == sk-ant-* ]] || { echo "does not look like an Anthropic key" >&2; exit 1; }

# Validate BEFORE swapping (cheap, read-only endpoint). The key goes through
# curl's stdin config, not argv, so it never shows up in `ps`.
code=$(curl -sS -o /dev/null -w '%{http_code}' --config - <<EOF
url = "https://api.anthropic.com/v1/models"
header = "x-api-key: $NEW"
header = "anthropic-version: 2023-06-01"
EOF
)
[[ "$code" == 200 ]] || { echo "validation failed (HTTP $code) — nothing changed" >&2; exit 1; }

fp() { printf '%s' "$(cat "$1")" | sha256sum | cut -c1-12; }   # same as Secret.fingerprint()
old_fp=$( [[ -f "$SECRET" ]] && fp "$SECRET" || echo none )
tmp=$(mktemp "$(dirname "$SECRET")/.anthropic.XXXXXX")
printf '%s\n' "$NEW" > "$tmp"
chown "$UID_ORCH:$UID_ORCH" "$tmp"; chmod 0400 "$tmp"
mv -f "$tmp" "$SECRET"                       # atomic on the same filesystem
unset NEW
new_fp=$(fp "$SECRET")
echo "rotated: key fingerprint $old_fp -> $new_fp"
echo "check:   grep '\"event\": \"startup\"' audit.jsonl | tail -1   (anthropic_key_fp should be $new_fp)"
