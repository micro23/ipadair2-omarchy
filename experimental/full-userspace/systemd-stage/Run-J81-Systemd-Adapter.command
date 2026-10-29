#!/bin/zsh
# J81 rootfs systemd policy dry-run. No boot, storage changes or PID1 switch.
set -u
HERE="$(cd "$(dirname "$0")" && pwd -P)"
PROJECT="$(cd "$HERE/../.." && pwd -P)"
EXPECTED="$HOME/ChatGPT-Projects/iPad-Air2-Omarchy"
if [[ "$PROJECT" != "$EXPECTED" ]]; then
  print "STOP: Unzip this folder inside $EXPECTED/Current first."
  exit 1
fi
PY=/opt/homebrew/bin/python3.13
if [[ ! -x "$PY" ]]; then
  print "STOP: Python 3.13 is not installed at $PY"
  exit 1
fi
print "Python selected: $PY"
print "Project: $PROJECT"
print "Only temporary RAM overlay changes; no iPad storage or boot changes."
PATH="/opt/homebrew/bin:$PATH" "$PY" "$HERE/j81_systemd_adapter_stage.py"
RESULT=$?
print ''
print "Report: $PROJECT/Reports/J81-SYSTEMD-ADAPTER-STAGE-V1_1-RESULT.txt"
if [[ -t 0 ]]; then
  read -k1 'key?Press any key to close this Terminal window...'
  print ''
fi
exit "$RESULT"
