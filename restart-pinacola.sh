#!/bin/bash
# Restart the Piña Colada dashboard as root.
# Run directly on the Pi: sudo bash /opt/pineapple/restart-pinacola.sh
pkill -KILL -f 'python3 /opt/pineapple/pinacola.py' 2>/dev/null
pkill -KILL -f 'python3 pinacola.py' 2>/dev/null
sleep 1
find /opt/pineapple -name '__pycache__' -exec rm -rf {} + 2>/dev/null
chmod 640 /opt/pineapple/.htpasswd 2>/dev/null
chgrp pi /opt/pineapple/.htpasswd 2>/dev/null
nohup python3 /opt/pineapple/pinacola.py >/var/log/pinacola.log 2>&1 &
echo "Piña Colada started as root (PID $!)"
