#!/bin/sh
set -e
echo "Reloading systemd daemon..."
systemctl daemon-reload
echo "Enabling aegis service to start on boot..."
systemctl enable aegis.service
echo "Starting aegis service..."
systemctl start aegis.service
