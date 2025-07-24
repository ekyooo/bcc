# BCC Tools Requirements Matrix

This document provides a comprehensive overview of the requirements for each BCC tool, including probe types, kernel configurations, minimum kernel versions, and required privileges.

## Legend

**Probe Types:**
- `kprobe`: Kernel function probing
- `uprobe`: User-space function probing  
- `tracepoint`: Static kernel tracepoints
- `USDT`: User Statically Defined Tracing
- `PMC`: Performance Monitoring Counters
- `sysfs`: System filesystem access

**Privileges:**
- `root`: Requires root privileges
- `CAP_SYS_ADMIN`: Requires CAP_SYS_ADMIN capability
- `CAP_PERFMON`: Requires CAP_PERFMON capability (Linux 5.8+)

## Tools Requirements Matrix

| Tool | Probe Type | Kernel Config | Min Kernel | Privileges | Notes |
|------|------------|---------------|------------|------------|-------|
| **General Tools** |
| argdist | kprobe, uprobe | CONFIG_KPROBES, CONFIG_UPROBES | 4.1+ | root | |
| bashreadline | uprobe | CONFIG_UPROBES | 4.1+ | root | |
| bpflist | sysfs | CONFIG_BPF_SYSCALL | 4.1+ | root | |
| capable | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| criticalstat | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| deadlock | uprobe | CONFIG_UPROBES | 4.1+ | root | |
| inject | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| klockstat | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| opensnoop | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| reset-trace | sysfs | CONFIG_BPF_SYSCALL | 4.1+ | root | |
| stackcount | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| syncsnoop | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| threadsnoop | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| tplist | sysfs | CONFIG_TRACEPOINTS | 4.1+ | root | |
| trace | kprobe, uprobe | CONFIG_KPROBES, CONFIG_UPROBES | 4.1+ | root | |
| ttysnoop | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| **High-level Language Tools** |
| ucalls | uprobe | CONFIG_UPROBES | 4.1+ | root | |
| uflow | uprobe | CONFIG_UPROBES | 4.1+ | root | |
| ugc | USDT | CONFIG_UPROBES | 4.1+ | root | |
| uobjnew | USDT | CONFIG_UPROBES | 4.1+ | root | |
| ustat | USDT | CONFIG_UPROBES | 4.1+ | root | |
| uthreads | uprobe | CONFIG_UPROBES | 4.1+ | root | |
| **Memory and Process Tools** |
| execsnoop | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| exitsnoop | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| killsnoop | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| pidpersec | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| compactsnoop | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| drsnoop | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| memleak | uprobe | CONFIG_UPROBES | 4.1+ | root | |
| oomkill | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| readahead | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| shmsnoop | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| slabratetop | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| kvmexit | tracepoint | CONFIG_TRACEPOINTS, CONFIG_KVM | 4.1+ | root | KVM required |
| numasched | tracepoint | CONFIG_TRACEPOINTS, CONFIG_NUMA | 4.1+ | root | NUMA required |
| rdmaucma | kprobe | CONFIG_KPROBES, CONFIG_INFINIBAND | 4.1+ | root | RDMA required |
| **Performance and Time Tools** |
| dbslower | USDT | CONFIG_UPROBES | 4.1+ | root | |
| dbstat | USDT | CONFIG_UPROBES | 4.1+ | root | |
| mysqld_qslower | USDT | CONFIG_UPROBES | 4.1+ | root | |
| funccount | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| funcinterval | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| funclatency | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| funcslower | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| hardirqs | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| softirqs | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| softirqslower | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| syscount | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| ppchcalls | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | PowerPC only |
| **CPU and Scheduler Tools** |
| cpudist | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| cpuunclaimed | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| llcstat | PMC | CONFIG_PERF_EVENTS | 4.1+ | CAP_PERFMON | |
| profile | PMC | CONFIG_PERF_EVENTS | 4.1+ | CAP_PERFMON | |
| offcputime | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| offwaketime | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| wakeuptime | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| runqlat | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| runqlen | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| runqslower | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| wqlat | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| **Network and Sockets Tools** |
| gethostlatency | uprobe | CONFIG_UPROBES | 4.1+ | root | |
| bindsnoop | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| sofdsnoop | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| solisten | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| sslsniff | uprobe | CONFIG_UPROBES | 4.1+ | root | |
| tcpaccept | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| tcpconnect | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| tcpconnlat | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| tcplife | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| tcpstates | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| tcptracer | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| tcpcong | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| tcpdrop | kprobe, tracepoint | CONFIG_KPROBES, CONFIG_TRACEPOINTS | 4.1+ | root | |
| tcpretrans | kprobe, tracepoint | CONFIG_KPROBES, CONFIG_TRACEPOINTS | 4.1+ | root | |
| tcprtt | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| tcpsubnet | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| tcpsynbl | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| tcptop | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| mptcpify | kprobe | CONFIG_KPROBES, CONFIG_MPTCP | 4.1+ | root | MPTCP required |
| netqtop | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| **Storage and Filesystem Tools** |
| bitesize | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| biolatency | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| biotop | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| biopattern | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| biosnoop | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| mdflush | kprobe | CONFIG_KPROBES, CONFIG_MD | 4.1+ | root | MD RAID required |
| virtiostat | kprobe | CONFIG_KPROBES, CONFIG_VIRTIO | 4.1+ | root | VirtIO required |
| cachestat | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| cachetop | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| dcsnoop | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| dcstat | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| dirtop | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| filelife | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| filegone | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| fileslower | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| filetop | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| mountsnoop | tracepoint | CONFIG_TRACEPOINTS | 4.1+ | root | |
| vfscount | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| vfsstat | kprobe | CONFIG_KPROBES | 4.1+ | root | |
| btrfsdist | kprobe | CONFIG_KPROBES, CONFIG_BTRFS_FS | 4.1+ | root | Btrfs required |
| btrfsslower | kprobe | CONFIG_KPROBES, CONFIG_BTRFS_FS | 4.1+ | root | Btrfs required |
| ext4dist | kprobe | CONFIG_KPROBES, CONFIG_EXT4_FS | 4.1+ | root | ext4 required |
| ext4slower | kprobe | CONFIG_KPROBES, CONFIG_EXT4_FS | 4.1+ | root | ext4 required |
| nfsdist | kprobe | CONFIG_KPROBES, CONFIG_NFS_FS | 4.1+ | root | NFS required |
| nfsslower | kprobe | CONFIG_KPROBES, CONFIG_NFS_FS | 4.1+ | root | NFS required |
| xfsdist | kprobe | CONFIG_KPROBES, CONFIG_XFS_FS | 4.1+ | root | XFS required |
| xfsslower | kprobe | CONFIG_KPROBES, CONFIG_XFS_FS | 4.1+ | root | XFS required |
| zfsdist | kprobe | CONFIG_KPROBES | 4.1+ | root | ZFS module required |
| zfsslower | kprobe | CONFIG_KPROBES | 4.1+ | root | ZFS module required |

## Common Kernel Configurations

Most BCC tools require these basic kernel configurations:

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
```

For specific probe types:

```
# For kprobe-based tools
CONFIG_KPROBES=y
CONFIG_KPROBE_EVENTS=y

# For tracepoint-based tools  
CONFIG_TRACEPOINTS=y

# For uprobe-based tools
CONFIG_UPROBES=y
CONFIG_UPROBE_EVENTS=y

# For PMC-based tools
CONFIG_PERF_EVENTS=y
```

## Checking Your System

To check if your system supports the required features:

```bash
# Check kernel version
uname -r

# Check if BPF is enabled
ls /sys/fs/bpf/

# Check available tracepoints
ls /sys/kernel/debug/tracing/events/

# Check kprobe support
echo 'p:myprobe do_sys_open' > /sys/kernel/debug/tracing/kprobe_events
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
