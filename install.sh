#!/usr/bin/env bash
# Run as root on Ubuntu 22.04/24.04:  sudo bash install.sh
set -e
APP=/opt/isp-portal
apt-get update && apt-get install -y python3 python3-venv python3-pip tzdata snmp
mkdir -p $APP && cp -r ./* $APP/ && cd $APP
python3 -m venv venv
./venv/bin/pip install --upgrade pip && ./venv/bin/pip install -r requirements.txt
if [ ! -f .env ]; then
  ADMIN_PASS=$(python3 -c "import secrets;print(secrets.token_urlsafe(9))")
  cat > .env <<ENV
SECRET_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))")
ADMIN_USER=admin
ADMIN_PASS=$ADMIN_PASS
ENV
  chmod 600 .env
  echo ">>> Admin login: admin / $ADMIN_PASS   (change it in Settings)"
fi
cat > /etc/systemd/system/isp-portal.service <<UNIT
[Unit]
Description=ISP Customer Complaint Portal
After=network-online.target
[Service]
WorkingDirectory=$APP
EnvironmentFile=$APP/.env
ExecStart=$APP/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips='*'
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable isp-portal && systemctl restart isp-portal
echo ">>> Done. Open http://SERVER_IP:8000  |  Admin: http://SERVER_IP:8000/admin"
