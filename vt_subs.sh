#!/usr/bin/env bash
#
# vt_subs.sh — VirusTotal Subdomain Searcher
# Hack-Protect :: passive OSINT subdomain discovery via VirusTotal API v3
#
# Usage:    ./vt_subs.sh
#           The script interactively prompts for an API key and a domain.
#
# Requires: curl, jq
# -----------------------------------------------------------------------------

set -euo pipefail

# --- colors -------------------------------------------------------------------
if [ -t 1 ]; then
  C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_B=$'\e[36m'; C_0=$'\e[0m'
else
  C_R=""; C_G=""; C_Y=""; C_B=""; C_0=""
fi

info()  { printf '%s[*]%s %s\n' "$C_B" "$C_0" "$1"; }
ok()    { printf '%s[+]%s %s\n' "$C_G" "$C_0" "$1"; }
warn()  { printf '%s[!]%s %s\n' "$C_Y" "$C_0" "$1" >&2; }
err()   { printf '%s[x]%s %s\n' "$C_R" "$C_0" "$1" >&2; }

# --- banner -------------------------------------------------------------------
cat <<'BANNER'
 __     ___     ___       _
 \ \   / / |_  / __|_  _ | |__ ___
  \ \ / /|  _| \__ \ || || '_ (_-<
   \_V_/  \__| |___/\_,_||_.__/__/   Hack-Protect | VirusTotal Subdomain Searcher

   Web: https://hack-protect.si/   |   X: https://x.com/HackProtectLabs (@HackProtectLabs)
BANNER
echo

# --- dependency check ---------------------------------------------------------
for bin in curl jq; do
  command -v "$bin" >/dev/null 2>&1 || { err "Missing '$bin'. Install it and try again."; exit 1; }
done

# --- config file (stores the API key next to the script) ----------------------
# The key is kept in a separate 0600 file rather than hardcoded in this script,
# so it is not exposed if you share or commit the script.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/.vt_subs.conf"

# --- API key: load from config / env, otherwise prompt and offer to save ------
API_KEY=""
SAVED_KEY=0

if [ -n "${VT_API_KEY:-}" ]; then
  API_KEY="$VT_API_KEY"
  info "Using API key from the VT_API_KEY environment variable."
elif [ -f "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  API_KEY="$(. "$CONFIG_FILE" 2>/dev/null; printf '%s' "${VT_API_KEY:-}")"
  if [ -n "$API_KEY" ]; then
    SAVED_KEY=1
    info "Loaded saved API key from ${C_B}$(basename "$CONFIG_FILE")${C_0}"
  fi
fi

if [ -z "$API_KEY" ]; then
  printf '%s[?]%s Enter your VirusTotal API key: ' "$C_Y" "$C_0"
  read -r -s API_KEY
  echo
fi
[ -n "$API_KEY" ] || { err "API key is empty."; exit 1; }

# --- domain input -------------------------------------------------------------
printf '%s[?]%s Enter a domain (e.g. vulnweb.com): ' "$C_Y" "$C_0"
read -r DOMAIN
# strip any http(s):// prefix and trailing path / whitespace
DOMAIN="$(printf '%s' "$DOMAIN" | sed -E 's#^https?://##; s#/.*$##; s/[[:space:]]//g')"
[ -n "$DOMAIN" ] || { err "Domain is empty."; exit 1; }

# --- validate the API key -----------------------------------------------------
info "Validating API key ..."
TEST="$(curl -s -H "x-apikey: $API_KEY" \
  "https://www.virustotal.com/api/v3/domains/${DOMAIN}")"
if echo "$TEST" | jq -e '.error' >/dev/null 2>&1; then
  CODE="$(echo "$TEST" | jq -r '.error.code')"
  MSG="$(echo "$TEST"  | jq -r '.error.message')"
  err "API error: ${CODE} — ${MSG}"
  case "$CODE" in
    WrongCredentialsError|AuthenticationRequiredError)
      warn "The key is wrong or missing. Make sure you pasted the full 64-character key." ;;
    QuotaExceededError)
      warn "Quota exceeded (free tier: 4/min, 500/day). Wait and try again." ;;
  esac
  exit 1
fi
ok "Key is valid."

# --- offer to save the key for next time (only if not already saved) ----------
if [ "$SAVED_KEY" -eq 0 ] && [ -z "${VT_API_KEY:-}" ]; then
  printf '%s[?]%s Save this API key for next time? [y/N]: ' "$C_Y" "$C_0"
  read -r ANS
  case "$ANS" in
    [Yy]*)
      umask 077
      printf 'VT_API_KEY=%q\n' "$API_KEY" > "$CONFIG_FILE"
      chmod 600 "$CONFIG_FILE"
      ok "Saved to ${C_B}$(basename "$CONFIG_FILE")${C_0} (permissions 600). Delete that file to reset."
      ;;
    *)
      info "Not saved."
      ;;
  esac
fi

info "Searching subdomains for: ${C_B}${DOMAIN}${C_0}"
echo

# --- collect subdomains with pagination ---------------------------------------
OUTFILE="subs_${DOMAIN}_$(date +%Y%m%d_%H%M%S).txt"
URL="https://www.virustotal.com/api/v3/domains/${DOMAIN}/subdomains?limit=40"
PAGE=0
TOTAL=0
: > "$OUTFILE"

while [ -n "$URL" ] && [ "$URL" != "null" ]; do
  PAGE=$((PAGE + 1))
  RESP="$(curl -s -H "x-apikey: $API_KEY" "$URL")"

  # error mid-pagination (e.g. quota)
  if echo "$RESP" | jq -e '.error' >/dev/null 2>&1; then
    warn "Stopped on page $PAGE: $(echo "$RESP" | jq -r '.error.code')"
    break
  fi

  COUNT="$(echo "$RESP" | jq -r '.data | length')"
  echo "$RESP" | jq -r '.data[].id' >> "$OUTFILE"
  TOTAL=$((TOTAL + COUNT))
  info "Page $PAGE: +$COUNT subdomains (total $TOTAL)"

  URL="$(echo "$RESP" | jq -r '.links.next // "null"')"

  # rate-limit delay only if another page follows
  if [ -n "$URL" ] && [ "$URL" != "null" ]; then
    sleep 15
  fi
done

# --- output & summary ---------------------------------------------------------
sort -u "$OUTFILE" -o "$OUTFILE"
UNIQ="$(wc -l < "$OUTFILE" | tr -d ' ')"

echo
ok "Done. Found ${C_B}${UNIQ}${C_0} unique subdomains."
ok "Saved to: ${C_B}${OUTFILE}${C_0}"
echo
if [ "$UNIQ" -gt 0 ]; then
  info "Subdomain list:"
  cat "$OUTFILE"
else
  warn "Nothing found (VirusTotal has no records for this domain)."
fi
