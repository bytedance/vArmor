#!/bin/bash

# Uninstall K3s
echo "Uninstalling K3s..."
/usr/local/bin/k3s-killall.sh
/usr/local/bin/k3s-uninstall.sh

# Check if K3s is uninstalled successfully
if [ $? -eq 0 ]; then
    echo "K3s uninstalled successfully."
else
    echo "Failed to uninstall K3s."
    exit 1
fi