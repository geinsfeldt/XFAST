# XFAST: XDP Feature Adaptive Selection Tool

**XFAST** is a research prototype that leverages **eBPF/XDP** (eXpress Data Path) for high-performance network data collection, combined with a **Genetic Algorithm (GA)** for intelligent **feature selection** directly at the kernel level. The system is designed for applications such as anomaly detection, traffic filtering, and adaptive monitoring in high-speed networks.

The system uses the CIC-IDS-2017 dataset for evaluation.

## 📦 Project Structure

    xdp-ga/
    ├── ebpf/
    │ ├── xdp_kern_feature_extract.c # eBPF kernel program
    │ ├── xdp_user.c # User-space loader and controller
    │ ├── xdp_miniga.h #  Shared structures and configurations for GA
    │ ├── common_kern_user.h # Shared structures and configurations for feature extracting
    │ ├── Makefile # Build and load XDP program
    │ ├── create_ga_population.c # Program to generate first generation popualtion for GA
    | └── test/
    |   ├── create_test_interface.sh # Create tests interfaces
    |   └── simulator.py # Run simulations and save results
    ├── model/
    │ └── model.py # ML models to get thresholds and test GA results
    ├── README.md
    └── LICENSE

## 🚀 How It Works

1. **XDP Kernel Program** (`xdp_kern_feature_extract.c`):
   - Captures incoming packets at the earliest point in the kernel stack.
   - Extracts relevant features based on selected gene bits.
   - Records timing, count, and flow information in BPF maps.
   - Evolves feature sets across generations.
   - Evaluates individuals using a custom fitness function based on traffic behavior.
   - Selects optimal feature subsets for the XDP program.

2. **User-Space Controller** (`xdp_user.c`):
   - Loads the XDP program into the network interface.
   - Reads data from BPF maps and passes it to the GA.


## ⚙️ Build & Run

    Make code:
        make

    Create interface:
        sudo ./create_test_interface.sh

    Run code:
        sudo ./xdp_user test1

    Delete xdp:
        sudo ip link set dev test1 xdp off

    Steps simulator:
        sudo python3 packet_simulator.py 

    Check info:
        sudo tcpdump -i test1 -n

    Check ebpf prints:
        sudo cat /sys/kernel/debug/tracing/trace_pipe

    Adapt dataset CIC-IDS-2017:
        editcap -F libpcap -T ether -s 1514 ~/Wednesday-workingHours.pcap ~/Wednesday-workingHours-xdp.pcap

    Run tcpreplay:
        sudo tcpreplay --intf1=test0 ~/Wednesday-workingHours-XDP.pcap

### Requirements

    sudo apt install make
    sudo apt install clang llvm libelf-dev libpcap-dev build-essential libc6-dev-i386
    sudo apt install linux-headers-$(uname -r)
    sudo apt install uthash-dev
    sudo apt install linux-tools-common linux-tools-generic
    sudo apt install tcpdump
    sudo apt-get install -y libbpf-dev
    sudo apt install tcpreplay