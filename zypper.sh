#!/bin/sh -xe

sudo zypper -n update
sudo zypper -n install -t pattern \
    devel_basis \
    devel_C_C++ \
    devel_kernel
sudo zypper -n install \
    libelf-devel \
    bc \
    usbutils \
    pciutils \
    systemtap \
    kernel-source \
    git \
    vim-data \
    cscope \
    strace

# Maybe:
#
#    kernel-default
#    kernel-default-base
#    kernel-default-devel
