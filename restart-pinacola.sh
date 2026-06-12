#!/bin/bash
# Restart the Piña Colada dashboard as root.
# Usage (from local machine):
#   sshpass -p 'SSH_PASS' ssh -p 2222 pi@10.42.0.95 "sudo bash /opt/pineapple/restart-pinacola.sh"
# Or directly on the Pi: sudo bash /opt/pineapple/restart-pinacola.sh
find /opt/pineapple -name '__pycache__' -exec rm -rf {} + 2>/dev/null
chmod 640 /opt/pineapple/.htpasswd 2>/dev/null
chgrp pi /opt/pineapple/.htpasswd 2>/dev/null
systemctl restart pineapple-express
echo "Piña Colada restarted via systemd"
systemctl status pineapple-express --no-pager | grep -E 'Active|Main PID'
