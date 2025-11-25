#!/bin/bash
# Check if a version number is provided as an argument
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <k8s_version>"
    exit 1
fi

K8S_VERSION=$1

# Install K3s with the specified version
echo "Installing K3s version $K8S_VERSION..."
curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="v$K8S_VERSION+k3s1" K3S_KUBECONFIG_MODE="644" INSTALL_K3S_EXEC="--disable=traefik" sh -

# Check if K3s is installed successfully
if [ $? -eq 0 ]; then
    echo "K3s version $K8S_VERSION installed successfully."
else
    echo "Failed to install K3s version $K8S_VERSION."
    exit 1
fi
mkdir -p ~/.kube/
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
k3s kubectl get node