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
fi

# Clean up Docker images
echo "Cleaning up Docker images..."
docker images -q | while read image_id; do
    echo "Removing image: $image_id"
    docker rmi -f "$image_id" 2>/dev/null || echo "Failed to remove image: $image_id"
done
echo "Docker image cleanup completed."
