#!/usr/bin/env python3
import json
import os
import subprocess, statistics, csv, re, time, psutil, signal
from pathlib import Path

# ---------- CONFIG ----------
XDP_USER = "./xdp_user"
XDP_ARGS   = ["test1"]
PCAP = "/home/gus/Downloads/Wednesday-workingHours-xdp.pcap"
MAP_PIN = "/sys/fs/bpf/xdp_times_map"
IFACE     = "test0"

N_RUNS   = 10
DURATION = 60      # s
INTERVAL = 1       # s
OUT_DIR  = Path("results"); OUT_DIR.mkdir(exist_ok=True)
# ----------------------------

def get_xdp_stats() -> dict | None:
    """
    Read the pinned XDP map and return the values.
    """
    try:
        out = subprocess.check_output(
            ["bpftool", "-j", "map", "dump", "pinned", MAP_PIN],
            text=True
        )
        for entry in json.loads(out):
            if entry["formatted"]["key"] == 0:
                value = entry["formatted"]["value"]
                return {"cnt": value["cnt"], "sum_ns": value["sum_ns"]}
        print("No key [0] found in map.")
    except subprocess.CalledProcessError as e:
        print("Error executing bpftool:\n", e.stderr)
    return None


def start_xdp_user() -> subprocess.Popen:
    return subprocess.Popen(
        [str(XDP_USER), *XDP_ARGS],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


def start_traffic(run_idx: int) -> subprocess.Popen:
    log_file = OUT_DIR / f"tcpreplay_run_{run_idx}.log"
    lf = log_file.open("w")
    return subprocess.Popen(
        ["tcpreplay", "-q", "-i", IFACE, "--loop=0", PCAP],
        stdout=lf, stderr=subprocess.STDOUT
    )


def collect_one_run(idx: int) -> tuple[float, float, float]:
    """
    Execute o xdp_user e coleta estatísticas do mapa pinado.
    Retorn (avg_ns, avg_cpu%, avg_mem%).
    """
    csv_path = OUT_DIR / f"run_{idx}.csv"
    psutil.cpu_percent()  # discard initial value

    prev = get_xdp_stats() or {"cnt": 0, "sum_ns": 0}
    ns_samples, cpu_samples, mem_samples = [], [], []

    traffic = start_traffic(idx)
    start = time.time()

    with csv_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["elapsed_s", "cpu_%", "mem_%", "delta_cnt",
                    "delta_sum_ns", "avg_ns"])

        while (elapsed := time.time() - start) < DURATION:
            cpu = psutil.cpu_percent(interval=INTERVAL)
            mem = psutil.virtual_memory().percent

            cur = get_xdp_stats()
            if not cur:
                print("map is empty; ignoring sample.")
                continue

            delta_cnt = cur["cnt"]    - prev["cnt"]
            delta_sum = cur["sum_ns"] - prev["sum_ns"]
            prev = cur

            avg_ns = delta_sum / delta_cnt if delta_cnt else 0
            ns_samples.append(avg_ns); cpu_samples.append(cpu); mem_samples.append(mem)

            w.writerow([round(elapsed, 2), cpu, mem,
                        delta_cnt, delta_sum, round(avg_ns, 2)])

    # end tcpreplay
    if traffic.poll() is None:
        traffic.send_signal(signal.SIGINT)
        traffic.wait()

    # summary to csv
    with csv_path.open("a", newline="") as f:
        w = csv.writer(f)
        w.writerow([])
        w.writerow(["summary_means",
                    statistics.mean(cpu_samples) if cpu_samples else 0,
                    statistics.mean(mem_samples) if mem_samples else 0,
                    "", "", statistics.mean(ns_samples) if ns_samples else 0])

    return (statistics.mean(ns_samples) if ns_samples else 0,
            statistics.mean(cpu_samples) if cpu_samples else 0,
            statistics.mean(mem_samples) if mem_samples else 0)


def main():
    if os.geteuid() != 0:
        print("Run with sudo: sudo python3 simulator.py")
        return

    all_ns, all_cpu, all_mem = [], [], []

    for i in range(1, N_RUNS + 1):
        print(f"\n=== Executing {i}/{N_RUNS} ===")
        xdp = start_xdp_user(); time.sleep(1)  # time for xdp_user to start

        avg_ns, avg_cpu, avg_mem = collect_one_run(i)
        all_ns.append(avg_ns); all_cpu.append(avg_cpu); all_mem.append(avg_mem)
        print(f"[run {i}] avg_ns={avg_ns:,.2f}  cpu%={avg_cpu:.2f}  mem%={avg_mem:.2f}")

        if xdp.poll() is None:
            xdp.send_signal(signal.SIGINT)
            xdp.wait()

    # global statistics
    def stats(lst): return (statistics.mean(lst),
                            statistics.stdev(lst) if len(lst) > 1 else 0)

    ns_m, ns_sd   = stats(all_ns)
    cpu_m, cpu_sd = stats(all_cpu)
    mem_m, mem_sd = stats(all_mem)

    print("\n=== Resume ===")
    print(f"Mean exec time (ns): {ns_m:,.2f} ± {ns_sd:,.2f}")
    print(f"Mean CPU   (%):     {cpu_m:.2f} ± {cpu_sd:.2f}")
    print(f"Mean Memory (%):   {mem_m:.2f} ± {mem_sd:.2f}")
    print(f"CSVs and logs in: {OUT_DIR.resolve()}")


if __name__ == "__main__":
    main()