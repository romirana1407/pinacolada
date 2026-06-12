#!/bin/bash
# Restart the Piña Colada dashboard as root.
# Usage (from local machine):
#   ssh -p 2222 pi@10.42.0.95 "sudo bash /opt/pinacola/restart-pinacola.sh"
# Or directly on the host: sudo bash restart-pinacola.sh
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Pick whichever dashboard service is installed (canonical: pinacola; legacy: pineapple-express)
SVC=pinacola
systemctl list-unit-files 2>/dev/null | grep -q '^pinacola\.service' || SVC=pineapple-express
find "$DIR" -name '__pycache__' -exec rm -rf {} + 2>/dev/null
chmod 640 "$DIR/.htpasswd" 2>/dev/null
systemctl restart "$SVC"
echo "Piña Colada restarted via systemd ($SVC)"
systemctl status "$SVC" --no-pager | grep -E 'Active|Main PID'
