#!/bin/bash
# Setup TPM-secured Yggdrasil as systemd service - FIXED

# Copy startup script with correct name
sudo cp yggdrasil-tpm-startup.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/yggdrasil-tpm-startup.sh

# Create TPM data directory
sudo mkdir -p /tpmdata
sudo chown $(whoami):$(whoami) /tpmdata

# Backup original service
sudo cp /lib/systemd/system/yggdrasil.service /lib/systemd/system/yggdrasil.service.backup

# Create new service file
sudo tee /lib/systemd/system/yggdrasil.service <<EOF
[Unit]
Description=Yggdrasil Network (TPM-secured)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/yggdrasil-tpm-startup.sh
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
Restart=on-failure
RestartSec=5
User=root

# Allow access to TPM and memory
ReadWritePaths=/etc/yggdrasil /dev/shm /var/run /run
PrivateDevices=false

# Security
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl enable yggdrasil
sudo systemctl restart yggdrasil

echo "TPM-secured Yggdrasil service configured correctly"