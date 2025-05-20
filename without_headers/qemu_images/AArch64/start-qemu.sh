#!/bin/sh

exec qemu-system-aarch64 -M virt -cpu cortex-a53 -nographic -smp 1 -kernel Image -append "nokaslr rootwait root=/dev/vda console=ttyAMA0" -drive file=rootfs.ext2,if=none,format=raw,id=hd0 -device virtio-blk-device,drive=hd0 -net nic,model=virtio -net user,hostfwd=tcp::2222-:22 ${EXTRA_ARGS} "$@" 
