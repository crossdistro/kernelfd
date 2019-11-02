#!/bin/sh -x

SRCVERSION=$(uname -r | sed 's/-default$//')
VERSION=$(uname -r)

pushd /usr/src/linux-$SRCVERSION
# Clean up
sudo make mrproper
# Apply distribution config
sudo cp /boot/config-$VERSION .config
sudo touch Module.symvers
sudo make olddefconfig
# Get ready for module building
sudo make modules_prepare
# Create empty Module.symvers file to avoid warning during a module build.
sudo touch Module.symvers
popd
