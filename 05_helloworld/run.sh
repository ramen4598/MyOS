#!/bin/bash
set -xue

QEMU=qemu-system-riscv32

# tired-i added
BASEDIR=$(dirname "$0")
BIOS_LOCATION=$BASEDIR/../opensbi-riscv32-generic-fw_dynamic.bin

# Path to clang and compiler flags
# mac Users:
# CC=/opt/homebrew/opt/llvm/bin/clang  
# Ubuntu users: 
CC=clang
CFLAGS="-std=c11 -O2 -g3 -Wall -Wextra --target=riscv32 -ffreestanding -nostdlib"

# Build the kernel
$CC $CFLAGS -Wl,-Tkernel.ld -Wl,-Map=kernel.map -o kernel.elf kernel.c

# Start QEMU
#$QEMU -machine virt -bios default -nographic -serial mon:stdio --no-reboot -kernel kernel.elf
$QEMU -machine virt -bios $BIOS_LOCATION -nographic -serial mon:stdio --no-reboot -kernel kernel.elf
