#!/bin/bash

# Copyright (c) 2018 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#---------------------------------------------------------------------
# Description: This script is the *ONLY* place where "qemu*" build options
# should be defined.
#
# Note to maintainers:
#
# XXX: Every option group *MUST* be documented explaining why it has
# been specified.
#---------------------------------------------------------------------

die() {
	>&2 echo -e "\e[31m$@\e[0m"
	exit 1
}

typeset -a qemu_options

qemu_version_file=VERSION
if [ ! -f ${qemu_version_file} ];then
	die "QEMU version file not found"
fi

qemu_version_major=$(cat ${qemu_version_file} | cut -d. -f1)
qemu_version_minor=$(cat ${qemu_version_file} | cut -d. -f2)
arch=${ARCH:-x86_64}

#---------------------------------------------------------------------
# Disabled options

# bluetooth support not required
qemu_options+=(--disable-bluez)

# braille support not required
qemu_options+=(--disable-brlapi)

# Don't build documentation
qemu_options+=(--disable-docs)

# Disable GUI (graphics)
qemu_options+=(--disable-curses)
qemu_options+=(--disable-gtk)
qemu_options+=(--disable-opengl)
qemu_options+=(--disable-sdl)
qemu_options+=(--disable-spice)
qemu_options+=(--disable-vte)

# Disable graphical network access
qemu_options+=(--disable-vnc)
qemu_options+=(--disable-vnc-jpeg)
qemu_options+=(--disable-vnc-png)
qemu_options+=(--disable-vnc-sasl)

# Disable unused filesystem support
qemu_options+=(--disable-fdt)
qemu_options+=(--disable-glusterfs)
qemu_options+=(--disable-libiscsi)
qemu_options+=(--disable-libnfs)
qemu_options+=(--disable-libssh2)

# Disable unused compression support
qemu_options+=(--disable-bzip2)
qemu_options+=(--disable-lzo)
qemu_options+=(--disable-snappy)

# SECURITY: Disable unused security options
qemu_options+=(--disable-seccomp)
qemu_options+=(--disable-tpm)

# Disable userspace network access ("-net user")
qemu_options+=(--disable-slirp)

# Disable USB
qemu_options+=(--disable-libusb)
qemu_options+=(--disable-usb-redir)

# Disable TCG support
qemu_options+=(--disable-tcg)

# SECURITY: Don't build a static binary (lowers security)
# needed if qemu version is less than 2.7
if [ ${qemu_version_major} -eq 2 ] && [ ${qemu_version_minor} -lt 7 ]; then
	qemu_options+=(--disable-static)
fi

# Disable debug
qemu_options+=(--disable-debug-tcg)
qemu_options+=(--disable-qom-cast-debug)
qemu_options+=(--disable-tcg-interpreter)
qemu_options+=(--disable-tcmalloc)

# SECURITY: Disallow network downloads
qemu_options+=(--disable-curl)

# Disable Remote Direct Memory Access (Live Migration)
# https://wiki.qemu.org/index.php/Features/RDMALiveMigration
qemu_options+=(--disable-rdma)

# Don't build the qemu-io, qemu-nbd and qemu-image tools
qemu_options+=(--disable-tools)

# Disable XEN driver
qemu_options+=(--disable-xen)

# FIXME: why is this disabled?
# (for reference, it's explicitly enabled in Ubuntu 17.10 and
# implicitly enabled in Fedora 27).
qemu_options+=(--disable-linux-aio)

#---------------------------------------------------------------------
# Enabled options

# Enable kernel Virtual Machine support.
# This is the default, but be explicit to avoid any future surprises
qemu_options+=(--enable-kvm)

# Required for fast network access
qemu_options+=(--enable-vhost-net)

# Always strip binaries
# needed if qemu version is less than 2.7
if [ ${qemu_version_major} -eq 2 ] && [ ${qemu_version_minor} -lt 7 ]; then
	qemu_options+=(--enable-strip)
fi

# Support Ceph RADOS Block Device (RBD)
qemu_options+=(--enable-rbd)

# In "passthrough" security mode
# (-fsdev "...,security_model=passthrough,..."), qemu uses a helper
# application called virtfs-proxy-helper(1) to make certain 9p
# operations safer.
qemu_options+=(--enable-virtfs)
qemu_options+=(--enable-attr)
qemu_options+=(--enable-cap-ng)

#---------------------------------------------------------------------
# Other options
qemu_options+=(--target-list=${arch}-softmmu)

# Set compile options
_qemu_cflags=""

# compile with high level of optimisation
_qemu_cflags+=" -O3"

# Improve code quality by assuming identical semantics for interposed
# synmbols.
_qemu_cflags+=" -fno-semantic-interposition"

# Performance optimisation
_qemu_cflags+=" -falign-functions=32"

# SECURITY: make the compiler check for common security issues
# (such as argument and buffer overflows checks).
_qemu_cflags+=" -D_FORTIFY_SOURCE=2"

# SECURITY: Create binary as a Position Independant Executable,
# and take advantage of ASLR, making ROP attacks much harder to perform.
# (https://wiki.debian.org/Hardening)
_qemu_cflags+=" -fPIE"

# Set linker options
_qemu_ldflags=""

# SECURITY: Link binary as a Position Independant Executable,
# and take advantage of ASLR, making ROP attacks much harder to perform.
# (https://wiki.debian.org/Hardening)
_qemu_ldflags+=" -pie"

# SECURITY: Disallow executing code on the stack.
_qemu_ldflags+=" -z noexecstack"

# SECURITY: Make the linker set some program sections to read-only
# before the program is run to stop certain attacks.
_qemu_ldflags+=" -z relro"

# SECURITY: Make the linker resolve all symbols immediately on program
# load.
_qemu_ldflags+=" -z now"

./configure $(echo ${qemu_options[@]}) --extra-cflags="${_qemu_cflags}" --extra-ldflags="${_qemu_ldflags}"
