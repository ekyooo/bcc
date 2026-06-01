# Cross-Compiling libbpf-tools

Cross-compile BCC CO-RE (Compile Once - Run Everywhere) libbpf-tools on
an x86\_64 host for a different target architecture.

The Linux kernel uses "arm64" as the architecture name while the GNU
toolchain uses "aarch64" as the triplet prefix. Both refer to the same
64-bit ARM architecture. This guide uses each where contextually
appropriate: `ARCH=arm64` for make, `aarch64-linux-gnu-` for the compiler.

## Quick Start (Debian/Ubuntu)

On Debian 11+ and Ubuntu 20.04+:

### 1. Register the foreign architecture and update apt

```bash
sudo dpkg --add-architecture arm64
```

On Ubuntu, the default apt sources only serve amd64/i386. You must add
a `[arch=arm64]` entry pointing to `ports.ubuntu.com` before `apt-get update`
will find arm64 packages. See the
[Ubuntu MultiArch wiki](https://wiki.ubuntu.com/MultiArch) for details.

On Debian, no extra source configuration is needed.

```bash
sudo apt-get update
```

### 2. Install packages

```bash
# Cross-compiler (install separately to avoid apt resolver conflicts)
sudo apt-get install -y gcc-aarch64-linux-gnu

# Target-arch libraries
sudo apt-get install -y libelf-dev:arm64 zlib1g-dev:arm64 libzstd-dev:arm64
```

> **Note**: The cross-compiler and target-arch `:arm64` packages must be
> installed in separate `apt-get` calls. On Ubuntu 24.04, combining them
> triggers an apt resolver conflict between `libc6-dev-arm64-cross` and
> `libc6-dev:arm64`.

Host build dependencies (clang, llvm, make, libelf-dev, zlib1g-dev) are the
same as for native builds — see [INSTALL.md](../INSTALL.md#ubuntu---source).

### 3. Build

```bash
cd libbpf-tools

# Dynamic linking
make CROSS_COMPILE=aarch64-linux-gnu-

# Static linking (specific tool)
make profile CROSS_COMPILE=aarch64-linux-gnu- EXTRA_LDFLAGS+=-static
```

### Supported Architectures

| ARCH        | CROSS\_COMPILE prefix     | Status   |
|-------------|--------------------------|----------|
| `arm64`     | `aarch64-linux-gnu-`     | Tested   |
| `riscv`     | `riscv64-linux-gnu-`     | Untested |
| `powerpc`   | `powerpc64le-linux-gnu-` | Untested |
| `s390`      | `s390x-linux-gnu-`       | Untested |
| `loongarch` | `loongarch64-linux-gnu-` | Untested |

Only architectures with pre-built `vmlinux.h` are listed.

---

## Other Distributions

Install the cross-compiler and target-arch libraries using your
distribution's package manager, then build with make.

### Required Libraries

**Target architecture** (cross-compiled libraries needed at **build time**):

- libelf, zlib (required)
- libzstd (required for static linking only)

These libraries must be built for the target architecture and installed
where the cross-linker can find them (e.g., `/usr/aarch64-linux-gnu/`).

### Building

```bash
cd libbpf-tools
make CROSS_COMPILE=aarch64-linux-gnu-
make profile CROSS_COMPILE=aarch64-linux-gnu- EXTRA_LDFLAGS+=-static
```

---

## Makefile Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CROSS_COMPILE` | (empty) | Cross-compiler prefix (e.g., `aarch64-linux-gnu-`) |
| `CC` | auto | `$(CROSS_COMPILE)gcc` when cross-compiling, `cc` natively |
| `ARCH` | auto | Derived from `CROSS_COMPILE` prefix; override with e.g., `ARCH=arm64` |
| `EXTRA_LDFLAGS` | (empty) | Add `-static` for static linking |

---

## Verifying

```bash
$ file profile
profile: ELF 64-bit LSB executable, ARM aarch64, ...
```

## Running on Target

```bash
scp profile user@target:/usr/local/bin/
ssh user@target sudo profile
```

Requirements:
- Linux kernel with eBPF support
- `CONFIG_DEBUG_INFO_BTF=y` recommended
- Dynamic binaries: libelf, zlib on target
- Static binaries: no additional dependencies

## vmlinux.h

Pre-built `vmlinux.h` headers are in architecture subdirectories
(e.g., `arm64/vmlinux.h`). If your target kernel differs significantly,
regenerate on the target:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```
