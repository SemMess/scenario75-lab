#!/usr/bin/env bash
#
# SCENARIO75 - Proxmox VM provisioning script.
# Author: Asyam Adithakarya Erdi Pribadi
#
# Run this on a fresh Debian/Ubuntu Linux VM (the intended guest OS on the
# Proxmox hypervisor). It installs Docker + Docker Compose, then builds and
# starts the full lab (vulnerable app, Blue Team SSH box, log injector).
#
# Usage:
#   sudo ./scripts/setup_proxmox_vm.sh
#
set -euo pipefail

echo "[1/4] Updating package index and installing prerequisites..."
apt-get update -y
apt-get install -y ca-certificates curl gnupg

echo "[2/4] Installing Docker Engine + Compose plugin..."
if ! command -v docker &> /dev/null; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  ARCH="$(dpkg --print-architecture)"
  CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")"
  echo \
    "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian ${CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
else
  echo "    Docker already installed, skipping."
fi

echo "[3/4] Verifying Docker is running..."
systemctl enable --now docker

echo "[4/4] Building and starting the lab (app + ssh-blue + log-injector)..."
cd "$(dirname "$0")/.."
docker compose build
docker compose up -d app ssh-blue
docker compose run --rm log-injector

echo ""
echo "Lab is up."
echo "  Vulnerable app:  http://<vm-ip>:3075"
echo "  Blue Team SSH:   ssh analyst@<vm-ip> -p 2275   (password: blue_team_rocks)"
echo "  Logs:            /opt/admin/logs (inside ssh-blue container, via the shared volume)"
