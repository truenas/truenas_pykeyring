#!/usr/bin/env bash

######################################################################
# Build and install pam_truenas in the VM
######################################################################

set -eu

echo "Building and installing pam_truenas..."

# Load VM info
source /tmp/vm-info.sh

# Wait for cloud-init to finish
echo "Waiting for cloud-init to complete..."
ssh debian@$VM_IP "cloud-init status --wait" || true

# Install rsync in VM first
echo "Installing rsync in VM..."
ssh debian@$VM_IP "sudo apt-get update && sudo apt-get install -y rsync"

# Copy source code to VM
echo "Copying source code to VM..."
ssh debian@$VM_IP "mkdir -p ~/truenas_pykeyring"
rsync -az --exclude='.git' --exclude='debian/.debhelper' \
  --exclude='src/.libs' --exclude='*.o' --exclude='*.lo' \
  "$GITHUB_WORKSPACE/" debian@$VM_IP:~/truenas_pykeyring/

# Install dependencies and build
echo "Installing dependencies in VM..."
ssh debian@$VM_IP 'bash -s' <<'REMOTE_SCRIPT'
set -eu

cd ~/truenas_pykeyring

# Update package lists
sudo apt-get update

# Install build dependencies
sudo apt-get install -y \
  build-essential \
  devscripts \
  debhelper \
  dh-autoreconf \
  dh-python \
  pkg-config \
  libpam0g-dev \
  libkeyutils-dev \
  uuid-dev \
  libssl-dev \
  libbsd-dev \
  libidn-dev \
  python3-dev \
  python3-all-dev \
  python3-pip \
  python3-setuptools \
  python3-build \
  python3-installer \
  python3-pytest \
  python3-pycryptodome \
  pybuild-plugin-pyproject \
  git

# Build and install truenas_pwenc
echo "Building truenas_pwenc..."
cd /tmp
git clone https://github.com/truenas/truenas_pwenc.git
cd truenas_pwenc
dpkg-buildpackage -us -uc -b
sudo dpkg -i ../libtruenas-pwenc1_*.deb
sudo dpkg -i ../libtruenas-pwenc-dev_*.deb
sudo dpkg -i ../python3-truenas-pwenc_*.deb

# Build and install truenas_pykeyring (with debug symbols)
echo "Building truenas_pykeyring..."
cd ~/truenas_pykeyring
dpkg-buildpackage -us -uc -b
sudo dpkg -i ../python3-truenas-pykeyring_*.deb

echo "Build and installation complete!"
REMOTE_SCRIPT

echo "truenas_pykeyring installed successfully in VM"
