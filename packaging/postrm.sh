#!/bin/sh
set -e
echo "Disabling aegis service..."
systemctl disable aegis.service || true
echo "Reloading systemd daemon..."
systemctl daemon-reload
