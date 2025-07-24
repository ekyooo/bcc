# BCC Tools Requirements Matrix

This document provides a comprehensive overview of the requirements for BCC tools, including both legacy Python-based tools (`tools/`) and modern CO-RE-based tools (`libbpf-tools/`).

## Legend

**Probe Types:**
- `kprobe`: Kernel function probing
- `uprobe`: User-space function probing  
- `tracepoint`: Static kernel tracepoints
- `USDT`: User Statically Defined Tracing
- `PMC`: Performance Monitoring Counters
- `sysfs`: System filesystem access
- `fentry/fexit`: Fast kernel function entry/exit tracing (BTF required)
- `raw_tracepoint`: Raw tracepoint access

**Privileges:**
- `root`: Requires root privileges
- `CAP_SYS_ADMIN`: Requires CAP_SYS_ADMIN capability
- `CAP_PERFMON`: Requires CAP_PERFMON capability (Linux 5.8+)
- `CAP_BPF`: Requires CAP_BPF capability (Linux 5.8+)

## Legacy Tools (`tools/`) - Python/BCC Framework

| Tool | Probe Type | Kernel Config | Min Kernel | Privileges | Notes |
|------|------------|---------------|------------|------------|-------|
| argdist | kprobe, uprobe | CONFIG_KPROBES, CONFIG_UPROBES | 4.1+ | root | |
| bashreadline | uprobe | CONFIG_UPROBES | 4.1+ | root | |
| bpflist | sysfs | CONFIG_BPF_SYSCALL | 4.1+ | root | |
| biolatency | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| biosnoop | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| biotop | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| bitesize | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| capable | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| cpudist | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| execsnoop | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| ext4slower | kprobe | CONFIG_KPROBES, CONFIG_EXT4_FS | 4.1+ | root | |
| funccount | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| funclatency | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| gethostlatency | uprobe | CONFIG_UPROBES | 4.1+ | root | |
| hardirqs | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| killsnoop | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| llcstat | PMC | CONFIG_PERF_EVENTS | 4.1+ | CAP_PERFMON | |
| opensnoop | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| profile | PMC | CONFIG_PERF_EVENTS | 4.1+ | CAP_PERFMON | |
| runqlat | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| softirqs | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| statsnoop | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| syscount | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| tcpaccept | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| tcpconnect | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| tcplife | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| tcpretrans | kprobe, tracepoint | CONFIG_KPROBES, CONFIG_TRACEPOINTS | 4.1+ | root | |
| trace | kprobe, uprobe | CONFIG_KPROBES, CONFIG_UPROBES | 4.1+ | root | |
| vfsstat | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| xfsslower | kprobe | CONFIG_KPROBES, CONFIG_XFS_FS | 4.1+ | root | |

## Modern CO-RE Tools (`libbpf-tools/`) - libbpf Framework

| Tool | Probe Type | Kernel Config | Min Kernel | Privileges | Notes |
|------|------------|---------------|------------|------------|-------|
| bashreadline | uprobe | CONFIG_UPROBES, CONFIG_DEBUG_INFO_BTF | 5.8+ | CAP_BPF | CO-RE enabled |
| biolatency | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| biopattern | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| biosnoop | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| biostacks | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| biotop | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| bitesize | fentry/fexit | CONFIG_DEBUG_INFO_BTF | 5.5+ | CAP_BPF | BTF required |
| capable | fentry/fexit | CONFIG_DEBUG_INFO_BTF | 5.5+ | CAP_BPF | |
| cpudist | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| cpufreq | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| drsnoop | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| execsnoop | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| exitsnoop | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| ext4dist | fentry/fexit | CONFIG_DEBUG_INFO_BTF, CONFIG_EXT4_FS | 5.5+ | CAP_BPF | |
| filetop | fentry/fexit | CONFIG_DEBUG_INFO_BTF | 5.5+ | CAP_BPF | |
| funclatency | fentry/fexit | CONFIG_DEBUG_INFO_BTF | 5.5+ | CAP_BPF | |
| gethostlatency | uprobe | CONFIG_UPROBES, CONFIG_DEBUG_INFO_BTF | 5.8+ | CAP_BPF | |
| hardirqs | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| killsnoop | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| klockstat | fentry/fexit | CONFIG_DEBUG_INFO_BTF | 5.5+ | CAP_BPF | |
| ksnoop | fentry/fexit | CONFIG_DEBUG_INFO_BTF | 5.5+ | CAP_BPF | |
| llcstat | PMC | CONFIG_PERF_EVENTS, CONFIG_DEBUG_INFO_BTF | 5.8+ | CAP_PERFMON | |
| mdflush | fentry/fexit | CONFIG_DEBUG_INFO_BTF, CONFIG_MD | 5.5+ | CAP_BPF | |
| mountsnoop | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| numamove | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF, CONFIG_NUMA | 5.2+ | CAP_BPF | |
| oomkill | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| opensnoop | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| pidpersec | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| profile | PMC | CONFIG_PERF_EVENTS, CONFIG_DEBUG_INFO_BTF | 5.8+ | CAP_PERFMON | |
| readahead | fentry/fexit | CONFIG_DEBUG_INFO_BTF | 5.5+ | CAP_BPF | |
| runqlat | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| runqlen | fentry/fexit | CONFIG_DEBUG_INFO_BTF | 5.5+ | CAP_BPF | |
| runqslower | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| sigsnoop | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| slabratetop | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| softirqs | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| solisten | fentry/fexit | CONFIG_DEBUG_INFO_BTF | 5.5+ | CAP_BPF | |
| statsnoop | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| syscount | raw_tracepoint | CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| tcpaccept | fentry/fexit | CONFIG_DEBUG_INFO_BTF | 5.5+ | CAP_BPF | |
| tcpconnect | fentry/fexit | CONFIG_DEBUG_INFO_BTF | 5.5+ | CAP_BPF | |
| tcpconnlat | fentry/fexit | CONFIG_DEBUG_INFO_BTF | 5.5+ | CAP_BPF | |
| tcpdrop | tracepoint, fentry/fexit | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.5+ | CAP_BPF | |
| tcplife | fentry/fexit | CONFIG_DEBUG_INFO_BTF | 5.5+ | CAP_BPF | |
| tcpretrans | tracepoint, fentry/fexit | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.5+ | CAP_BPF | |
| tcprtt | fentry/fexit | CONFIG_DEBUG_INFO_BTF | 5.5+ | CAP_BPF | |
| tcpstates | tracepoint | CONFIG_TRACEPOINTS, CONFIG_DEBUG_INFO_BTF | 5.2+ | CAP_BPF | |
| tcpsynbl | fentry/fexit | CONFIG_DEBUG_INFO_BTF | 5.5+ | CAP_BPF | |
| vfsstat | fentry/fexit | CONFIG_DEBUG_INFO_BTF | 5.5+ | CAP_BPF | |

## Key Differences: Legacy vs CO-RE Tools

### Legacy Tools (`tools/`)
- **Framework**: Python + BCC (LLVM JIT compilation at runtime)
- **Portability**: Requires LLVM/Clang on target system
- **Kernel Support**: Linux 4.1+
- **BTF Requirement**: Not required
- **Privileges**: Usually requires root
- **Probe Types**: Primarily kprobe, uprobe, tracepoint

### CO-RE Tools (`libbpf-tools/`)
- **Framework**: C + libbpf (pre-compiled, portable)
- **Portability**: Compile once, run everywhere (with BTF)
- **Kernel Support**: Linux 5.2+ (5.5+ for fentry/fexit)
- **BTF Requirement**: Required (`CONFIG_DEBUG_INFO_BTF=y`)
- **Privileges**: Can use fine-grained capabilities (CAP_BPF, CAP_PERFMON)
- **Probe Types**: fentry/fexit, raw_tracepoint, traditional types

## Common Kernel Configurations

### Basic BPF Support (Both)
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
```

### Legacy Tools Only
```
CONFIG_KPROBES=y
CONFIG_KPROBE_EVENTS=y
CONFIG_UPROBES=y  
CONFIG_UPROBE_EVENTS=y
CONFIG_TRACEPOINTS=y
```

### CO-RE Tools Additional Requirements
```
CONFIG_DEBUG_INFO_BTF=y          # Essential for CO-RE
CONFIG_DEBUG_INFO=y              # Required for BTF generation
CONFIG_BPF_LSM=y                 # Optional, for LSM programs
```

### Modern Capabilities (Linux 5.8+)
```
# Fine-grained capabilities instead of root
CAP_BPF=y
CAP_PERFMON=y
```

## Checking Your System

```bash
# Check kernel version
uname -r

# Check BTF availability (for CO-RE tools)
ls /sys/kernel/btf/vmlinux

# Check BPF capability support
zgrep CAP_BPF /proc/config.gz

# Check available fentry/fexit support
bpftool feature probe | grep fentry
```

## Recommendations

- **For new deployments**: Use CO-RE tools (`libbpf-tools/`) when possible
- **For older kernels**: Use legacy tools (`tools/`)
- **For development**: CO-RE tools offer better debugging and portability
- **For production**: CO-RE tools have lower runtime overhead and better security
echo 0 > /sys/kernel/debug/tracing/kprobe_events

# Check uprobe support
echo 'p:myuprobe /bin/bash:0x4245c0' > /sys/kernel/debug/tracing/uprobe_events
echo 0 > /sys/kernel/debug/tracing/uprobe_events
```

## Notes

- Most tools require root privileges or appropriate capabilities
- Some tools have additional dependencies on specific kernel modules or features
- Kernel version requirements may vary based on specific features used
- Some distributions may have different kernel configurations
