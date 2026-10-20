# NetScope Lab

NetScope Lab runs Nmap scans from a local web dashboard, parses the XML results, and displays discovered hosts, ports, services, and review findings. Importing an existing XML or JSON report remains available as an optional workflow.

## Install on Kali Linux

```bash
sudo apt update
sudo apt install -y nmap python3 python3-venv
cd /path/to/project1
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Start the application

For scan modes that work without raw-packet privileges:

```bash
source .venv/bin/activate
python run.py
```

For SYN, full, aggressive, or UDP scans that need elevated privileges, start the local app with sudo:

```bash
sudo .venv/bin/python run.py
```

Then open <http://127.0.0.1:5000>. The app listens on the local machine only. Stop it with `Ctrl+C` in the terminal. Live phase progress and Nmap's estimated time remaining appear while scanning. The browser remembers up to 12 recent targets and up to 12 complete scan configurations, including scan type and ports, so you can select a prior target or repeat a scan without retyping it.

Scan snapshots are saved in a local SQLite database under `instance/`. Use **Scan History** to reopen a previous result after restarting the app, or compare two snapshots to review newly seen hosts, newly open ports, ports no longer reported open, and changed service/version detections.

## Run a scan and view results

1. Open **Live Scan** (or **Start a Live Scan** from the empty dashboard).
2. Enter an IP address, CIDR range, Nmap IPv4 range, or hostname you own or are authorized to assess.
3. Choose a scan type and optionally enter ports such as `22,80,443` or `1-1024`.
4. Start the scan. The status page shows progress; when it finishes, choose **View Dashboard** to see the hosts, open ports, services, statistics, and findings. The Hosts, Findings, and Reports pages provide more detail and exports.

Scanning systems without permission may be unlawful. Use this tool only on systems and networks you own or have explicit authorization to test. Large or intensive scans can take a long time.

## Available scan modes

- **Ping Sweep** discovers responsive hosts without checking ports.
- **Quick Scan** checks common TCP ports.
- **Service Detection** attempts to identify services and versions.
- **SYN**, **Full**, **Aggressive**, and **UDP** modes may need root privileges and can generate more traffic.
- **Vulnerability Scripts** runs Nmap's `vuln` NSE category and can be intrusive; use only with explicit authorization.
- **TCP Connect** works without raw-packet privileges; **All TCP Ports** checks the complete TCP port range.
- **TCP + UDP** checks common ports for both protocols in one run; it requires elevated privileges.

## Scan controls

- Choose the scan profile's default port coverage, the top 100 or 1,000 ports, all ports, or a custom list/range.
- Select Nmap timing T2 (careful), T3 (balanced), or T4 (fast), and set a 30-minute, 1-hour, or 2-hour maximum runtime.
- Exclude a host or CIDR from a range scan, skip host discovery for systems that block probes, or disable reverse DNS lookups.
- Enter up to 256 IPs, hostnames, CIDRs, or ranges as comma-separated values or one target per line.
- Add light or intensive service/version probes, OS detection, route tracing, or Nmap's safe NSE script category.
- Scan progress follows Nmap's current phase; the estimated remaining time is approximate and may change as Nmap moves between phases.

All-ports, UDP, aggressive, and vulnerability-script scans can create substantial traffic and take a long time. Use them only within an authorized scope.

## Import and sample data

Use **Import** to load an existing Nmap XML report or a supported JSON scan report. Sample data can be loaded from the Import page for a demonstration; it is not loaded automatically at startup.
