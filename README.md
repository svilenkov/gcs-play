# gcs-play
Shadow stack experiments and test code for ARM64 Guarded Control Stack (GCS). For exploring, understanding, and validating GCS mechanisms

**Note:** Functions in this file are marked `static inline` intentionally. This was done in order to avoid surprises during disassembly or test instrumentation and keep stack as minimal as possible, reducing cognitive overhead when inspecting the control flow and understanding GCS behavior.

This is test code, not production logic, so predictability is prefered. Additionally
disabling ASLR `echo 0 > /proc/sys/kernel/randomize_va_space` during inspection ensures
memory addresses remain consistent across different code revisions, which is super useful to avoid
distractions during analysis.

TODO: Give a TL;DR of what the test covers

## Deploy to FVP (simulator)
I usually have it running with an SSH server and the `linux-tools` dir from the kernel sources copied to the root's home dir so simply:
```bash
rsync -rvz -e 'ssh -p 2222' --progress gcs-simple.c root@192.168.96.131:/root/linux-tools/testing/selftests/arm64/gcs/gcs-simple.c
```

## Building (inside FVP)

### Makefile
Add target to Makefile inside the simulator if you don't have setup a faster
choor build env.
```make
$(OUTPUT)/gcs-simple: gcs-simple.c
	$(CC) -g -fno-asynchronous-unwind-tables -fno-ident -Os -nostdlib \
		-static -include ../../../../include/nolibc/nolibc.h \
		-I../../../../../usr/include \
		-std=gnu99 -I../.. -g \
		-ffreestanding -Wall $^ -o $@ -lgcc

```

### Command

```bash
cd /root/linux-tools/testing/selftests/arm64/gcs
make CFLAGS="-I../../../selftests -I../../../../../linux-tools/include" $PWD/gcs-simples
```
