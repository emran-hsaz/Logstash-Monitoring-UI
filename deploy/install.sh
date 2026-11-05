#!/usr/bin/env bash
# Install lsmon (and optionally lsdash) on a Logstash host.
#
#   sudo ./deploy/install.sh                 # lsmon + 30s systemd timer
#   sudo ./deploy/install.sh --dashboard     # also install the lsdash service (not started)
#   sudo ./deploy/install.sh --uninstall     # remove everything except the metrics log
#
# Needs only python3 and systemd. Nothing is downloaded, so it works air-gapped.
# Logstash itself is never touched: no config, JVM or pipeline files are changed.
set -euo pipefail

PREFIX=/opt/lsmon
RUN_USER="${RUN_USER:-logstash}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DASHBOARD=0
UNINSTALL=0

for arg in "$@"; do
  case "$arg" in
    --dashboard) DASHBOARD=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)" >&2; exit 1; }

if [ "$UNINSTALL" -eq 1 ]; then
  systemctl disable --now lsmon.timer lsdash.service 2>/dev/null || true
  rm -f /etc/systemd/system/lsmon.service /etc/systemd/system/lsmon.timer /etc/systemd/system/lsdash.service
  systemctl daemon-reload
  rm -f /usr/local/bin/lsmon /usr/local/bin/lsdash /etc/logrotate.d/lsmon
  rm -rf "$PREFIX" /var/lib/lsmon
  echo "Removed lsmon. Kept /etc/lsmon and /var/log/lsmon - delete them yourself if you no longer need them."
  exit 0
fi

command -v python3 >/dev/null || { echo "python3 not found" >&2; exit 1; }
id "$RUN_USER" >/dev/null 2>&1 || { echo "user '$RUN_USER' not found; set RUN_USER=..." >&2; exit 1; }

install -d -m 0755 "$PREFIX"
install -m 0755 "$HERE/lsmon.py" "$HERE/lsdash.py" "$PREFIX/"
ln -sf "$PREFIX/lsmon.py" /usr/local/bin/lsmon
ln -sf "$PREFIX/lsdash.py" /usr/local/bin/lsdash

install -d -o "$RUN_USER" -g "$RUN_USER" -m 0750 /var/lib/lsmon /var/log/lsmon
install -d -m 0750 -g "$RUN_USER" /etc/lsmon
[ -f /etc/lsmon/lsmon.env ] || install -m 0640 -g "$RUN_USER" "$HERE/examples/lsmon.env.example" /etc/lsmon/lsmon.env

sed "s/^User=.*/User=$RUN_USER/; s/^Group=.*/Group=$RUN_USER/" "$HERE/deploy/systemd/lsmon.service" > /etc/systemd/system/lsmon.service
install -m 0644 "$HERE/deploy/systemd/lsmon.timer" /etc/systemd/system/lsmon.timer
sed "s/logstash logstash/$RUN_USER $RUN_USER/g" "$HERE/deploy/logrotate/lsmon" > /etc/logrotate.d/lsmon

if [ "$DASHBOARD" -eq 1 ]; then
  sed "s/^User=.*/User=$RUN_USER/; s/^Group=.*/Group=$RUN_USER/" "$HERE/deploy/systemd/lsdash.service" > /etc/systemd/system/lsdash.service
  [ -f /etc/lsmon/lsdash.json ] || install -m 0640 -g "$RUN_USER" "$HERE/examples/lsdash.example.json" /etc/lsmon/lsdash.json
  [ -f /etc/lsmon/lsdash.env ] || install -m 0640 -g "$RUN_USER" "$HERE/examples/lsdash.env.example" /etc/lsmon/lsdash.env
fi

systemctl daemon-reload
systemctl enable --now lsmon.timer

echo
echo "lsmon installed. Samples are logged every 30s to /var/log/lsmon/metrics.jsonl"
echo "  Live view:     lsmon --watch"
echo "  Recent log:    lsmon --history 20 --log-file /var/log/lsmon/metrics.jsonl"
echo "  API login:     edit /etc/lsmon/lsmon.env if your Logstash API needs one"
if [ "$DASHBOARD" -eq 1 ]; then
  echo
  echo "lsdash installed but not started. Next:"
  echo "  1. list your nodes in /etc/lsmon/lsdash.json"
  echo "  2. set LSDASH_USER / LSDASH_PASSWORD in /etc/lsmon/lsdash.env"
  echo "  3. systemctl enable --now lsdash"
fi
