// Userspace loader for the aya syscall tracer. Loads + attaches the eBPF program, then
// drains the per-(pid, syscall) map once per second and prints one JSON line per window:
//   {"<pid>": {"<syscall>": count, ...}, ...}
// This is the SAME contract tracer.py emits, so the Python features.py/detector.py pipeline
// can consume this binary's stdout unchanged -- a no-bcc, portable replacement for the probe.
use std::collections::BTreeMap;
use std::time::Duration;

use aya::maps::HashMap as AyaHashMap;
use aya::programs::TracePoint;
use log::debug;
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit for older kernels that don't use memcg-based accounting.
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: setrlimit with a valid &rlimit; failure is non-fatal and only logged.
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Include the compiled eBPF object at build time and load it at runtime.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/aya-tracer"
    )))?;

    let program: &mut TracePoint = ebpf.program_mut("aya_tracer").unwrap().try_into()?;
    program.load()?;
    program.attach("raw_syscalls", "sys_enter")?;
    eprintln!(
        "[*] aya tracer attached to raw_syscalls:sys_enter. \
         One JSON line of per-pid syscall counts per second. Ctrl-C to stop."
    );

    let mut window = tokio::time::interval(Duration::from_secs(1));
    window.tick().await; // the first tick fires immediately; skip it
    loop {
        tokio::select! {
            _ = window.tick() => drain_and_print(&mut ebpf)?,
            _ = signal::ctrl_c() => {
                eprintln!("[*] exiting");
                break;
            }
        }
    }
    Ok(())
}

/// Read the whole COUNTS map, aggregate per pid, print one JSON line, then clear it.
fn drain_and_print(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let mut counts: AyaHashMap<_, u64, u64> =
        AyaHashMap::try_from(ebpf.map_mut("COUNTS").expect("COUNTS map missing"))?;

    let mut per_pid: BTreeMap<u32, BTreeMap<u32, u64>> = BTreeMap::new();
    let mut keys: Vec<u64> = Vec::new();
    for item in counts.iter() {
        let (key, val) = item?;
        keys.push(key);
        let pid = (key >> 32) as u32;
        let syscall = (key & 0xffff_ffff) as u32;
        *per_pid.entry(pid).or_default().entry(syscall).or_insert(0) += val;
    }
    // Clear the window so counts don't accumulate across windows (mirrors map.clear()).
    for key in keys {
        let _ = counts.remove(&key);
    }

    let mut out = String::from("{");
    for (i, (pid, hist)) in per_pid.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!("\"{pid}\":{{"));
        for (j, (syscall, count)) in hist.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            out.push_str(&format!("\"{syscall}\":{count}"));
        }
        out.push('}');
    }
    out.push('}');
    println!("{out}");
    Ok(())
}
