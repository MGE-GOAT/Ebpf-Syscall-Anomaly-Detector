#![no_std]
#![no_main]

// Rust (aya) port of tracer.py's kernel half: attach to raw_syscalls:sys_enter and
// count per-(pid, syscall) into a BPF hash map. Userspace drains + clears it once per
// window -- exactly the bcc design, but as a portable, no-bcc binary.

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};

// Key packs the PID in the high 32 bits and the syscall number in the low 32 bits, so a
// single u64->u64 map carries the whole (pid, syscall) -> count table to userspace.
#[map]
static COUNTS: HashMap<u64, u64> = HashMap::with_max_entries(65536, 0);

#[tracepoint]
pub fn aya_tracer(ctx: TracePointContext) -> u32 {
    match try_aya_tracer(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_aya_tracer(ctx: TracePointContext) -> Result<u32, u32> {
    // raw_syscalls:sys_enter format -> `long id` (the syscall number) sits at offset 8.
    // SAFETY: offset 8 is within the tracepoint's fixed record layout; read_at does a
    // bounds-checked bpf_probe_read and returns Err if the kernel rejects it.
    let id: i64 = unsafe { ctx.read_at(8).map_err(|_| 1u32)? };
    if id < 0 {
        return Ok(0);
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let key = ((pid as u64) << 32) | (id as u64 & 0xffff_ffff);

    // Increment in the kernel map (verifier-friendly: bounded, no loops).
    match COUNTS.get_ptr_mut(&key) {
        // SAFETY: the pointer points into the map entry we just looked up; it is valid for
        // this program's duration and we only touch the single u64 it addresses.
        Some(counter) => unsafe { *counter += 1 },
        None => {
            let _ = COUNTS.insert(&key, &1, 0);
        }
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
