#!/bin/bash
set -xue

QEMU=qemu-system-riscv32
CFLAGS="-std=c11 -O2 -g3 -Wall -Wextra --target=riscv32 -ffreestanding -nostdlib"

# tired-i added
BASEDIR=$(dirname "$0")
BIOS_LOCATION=$BASEDIR/../opensbi-riscv32-generic-fw_dynamic.bin

# Path to clang and compiler flags
# mac Users:
# CC=/opt/homebrew/opt/llvm/bin/clang  
# Ubuntu users: 
CC=clang
CFLAGS="-std=c11 -O2 -g3 -Wall -Wextra --target=riscv32 -ffreestanding -nostdlib"

# Path to llvm-objcopy
# mac Users:
# OBJCOPY=/opt/homebrew/opt/llvm/bin/llvm-objcopy
# Ubuntu users: 
OBJCOPY=llvm-objcopy

# Build the shell (application)
$CC $CFLAGS -Wl,-Tuser.ld -Wl,-Map=shell.map -o shell.elf shell.c user.c common.c
$OBJCOPY --set-section-flags .bss=alloc,contents -O binary shell.elf shell.bin
$OBJCOPY -Ibinary -Oelf32-littleriscv shell.bin shell.bin.o

# Build the kernel
$CC $CFLAGS -Wl,-Tkernel.ld -Wl,-Map=kernel.map -o kernel.elf \
    kernel.c common.c shell.bin.o

# Start QEMU
#$QEMU -machine virt -bios default -nographic -serial mon:stdio --no-reboot -kernel kernel.elf
$QEMU -machine virt -bios $BIOS_LOCATION -nographic -serial mon:stdio --no-reboot -kernel kernel.elf

