#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// Event structure matching userspace definition
struct event_t {
    u64 timestamp;
    u32 pid;
    u32 uid;
    char comm[16];
    char args[256];
    u32 type; // 0=execve, 1=connect, 2=bind
    int return_code;
};

// Events ring buffer
BPF_RINGBUF_OUTPUT(events, 256);

// Track execve calls
TRACEPOINT_PROBE(sched, sched_process_exec) {
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = uid_gid & 0xFFFFFFFF;
    
    // Only log non-root or suspicious processes
    // In production: apply threat scoring
    
    struct event_t *event = events.ringbuf_reserve(sizeof(*event));
    if (!event)
        return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;
    event->type = 0; // execve
    event->return_code = 0;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    events.ringbuf_submit(event, 0);
    return 0;
}

// Track network connections
TRACEPOINT_PROBE(net, net_dev_xmit) {
    struct event_t *event = events.ringbuf_reserve(sizeof(*event));
    if (!event)
        return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->type = 1; // connect
    
    events.ringbuf_submit(event, 0);
    return 0;
}

// Track port bindings
TRACEPOINT_PROBE(syscalls, sys_enter_bind) {
    struct event_t *event = events.ringbuf_reserve(sizeof(*event));
    if (!event)
        return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->type = 2; // bind
    
    events.ringbuf_submit(event, 0);
    return 0;
}
