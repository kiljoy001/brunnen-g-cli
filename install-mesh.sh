#!/bin/bash
# Master installer for TPM-secured Yggdrasil mesh

echo "Installing Yggdrasil..."
./install_yggdrasil.sh

echo "Setting up systemd service..."
sudo ./setup-systemd.sh

echo "Testing service..."
sudo systemctl status yggdrasil

echo "Mesh network ready. Run ./brunnen-cli.sh to continue."