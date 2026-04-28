#!/bin/sh
set -e
echo "Stopping aegis service..."
systemctl stop aegis.service || true
