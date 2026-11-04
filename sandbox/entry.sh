#!/bin/sh
# Seed the decoy HOME (execute phase only) and hand over to launch, whose execve is the T0 marker
# the evidence normalizer uses to drop this setup work (docs/ARCHITECTURE.md 5.2, 7.3).
set -eu

if [ "${FIRSTRUN_PHASE:-execute}" = "execute" ] && [ -d /seed/home ]; then
  cp -r /seed/home/. "$HOME"/
  if [ -f /seed/perms.txt ]; then
    # Lines are "<octal mode> <path relative to HOME>"; the path may contain spaces.
    while read -r mode path; do
      case "$mode" in [0-7][0-7][0-7] | [0-7][0-7][0-7][0-7]) ;; *) continue ;; esac
      case "$path" in "" | /* | *..*) continue ;; esac
      chmod "$mode" "$HOME/$path" 2>/dev/null || true
    done < /seed/perms.txt
  fi
fi

cd "$HOME"
exec /opt/firstrun/launch
