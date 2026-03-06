#!/bin/bash
echo "Stopping Docker..."
sudo systemctl stop docker.socket docker.service
sudo pkill -9 dockerd
sudo pkill -9 containerd

echo "Cleaning up corrupted containers..."
sudo rm -rf /var/lib/docker/containers/*
sudo rm -rf /var/lib/docker/network/files/local-kv.db

echo "Writing Correct Cgroup Config..."
sudo mkdir -p /etc/docker
echo '{
  "exec-opts": ["native.cgroupdriver=systemd"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "30m"
  },
  "storage-driver": "overlay2"
}' | sudo tee /etc/docker/daemon.json >/dev/null

echo "Restarting Docker..."
sudo systemctl start docker.socket docker.service
sleep 5

echo "Deleting old Kind cluster..."
sudo kind delete cluster --name sentinel-core || true

echo "Applying kernel modules..."
sudo modprobe overlay
sudo modprobe br_netfilter
echo -e "net.bridge.bridge-nf-call-iptables  = 1\nnet.bridge.bridge-nf-call-ip6tables = 1\nnet.ipv4.ip_forward                 = 1" | sudo tee /etc/sysctl.d/k8s.conf >/dev/null
sudo sysctl --system >/dev/null

echo "Starting Kind cluster... (This usually takes 2-3 mins)"
sudo kind create cluster --name sentinel-core --config infra/kind-config.yaml --wait 5m
