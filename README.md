# NOC-OS — ISP NOC & Customer Support Portal

FastAPI-based ISP NOC and customer support application.

## Requirements
- Ubuntu/Debian Linux
- Python 3, venv and Git
- Reachable network devices and configured API/SNMP credentials

## Installation
```bash
git clone https://github.com/Netronixbd/NOC-OS.git
cd NOC-OS
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

Configure required environment variables before starting.

## Testing
```bash
./venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000
```

## Existing production service
```bash
sudo systemctl status isp-portal.service
sudo journalctl -u isp-portal.service -n 100 --no-pager
```

Use HTTPS, firewall restrictions, protected secrets and least-privilege
device credentials in production. Never commit tokens, passwords,
database files, customer data or private keys.

Features and configuration depend on the deployed application version.
Add the applicable project license before redistribution.
