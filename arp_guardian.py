#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║         ARP GUARDIAN - Spoofing Detection & Analyzer      ║
║     Simulate | Detect | Absorb Abnormal ARP Packets       ║
╚═══════════════════════════════════════════════════════════╝
  Educational / Security Research Tool
  Use only on networks you own or have explicit permission to test.
"""

import sys
import time
import random
import threading
import argparse
import ipaddress
import logging
from datetime import datetime
from collections import defaultdict

# ── Rich terminal UI ──────────────────────────────────────
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

# ── Scapy ─────────────────────────────────────────────────
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import (
    ARP, Ether, srp, sendp, sniff, get_if_list,
    conf as scapy_conf
)
from scapy.layers.l2 import getmacbyip

console = Console()

# ══════════════════════════════════════════════════════════
#  GLOBAL STATE
# ══════════════════════════════════════════════════════════
ip_mac_table   = {}          # Trusted: {ip: mac}
alert_log      = []          # [{time, type, src_ip, src_mac, msg}]
packet_stats   = defaultdict(int)
lock           = threading.Lock()

ALERT_THRESHOLD = 5          # packets/sec from same source = flood
flood_tracker   = defaultdict(list)


# ══════════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════════
def print_banner():
    banner = """
[bold cyan]
  █████╗ ██████╗ ██████╗      ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗
 ██╔══██╗██╔══██╗██╔══██╗    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║
 ███████║██████╔╝██████╔╝    ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║
 ██╔══██║██╔══██╗██╔═══╝     ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║
 ██║  ██║██║  ██║██║         ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝          ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
[/bold cyan]
[bold yellow]          ARP Spoofing Detector · Simulator · Packet Absorber[/bold yellow]
[dim]          Educational Security Research Tool | Use Responsibly[/dim]
"""
    console.print(banner)


# ══════════════════════════════════════════════════════════
#  UTILITIES
# ══════════════════════════════════════════════════════════
def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def random_mac():
    """Generate a random spoofed MAC address."""
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))

def is_broadcast(mac):
    return mac.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")

def add_alert(alert_type, src_ip, src_mac, msg, color="red"):
    with lock:
        alert_log.append({
            "time":    ts(),
            "type":    alert_type,
            "src_ip":  src_ip,
            "src_mac": src_mac,
            "msg":     msg,
            "color":   color,
        })
        if len(alert_log) > 200:
            alert_log.pop(0)


# ══════════════════════════════════════════════════════════
#  MODULE 1 – NETWORK SCANNER (build trusted table)
# ══════════════════════════════════════════════════════════
def scan_network(subnet: str):
    """ARP-scan the subnet and populate the trusted IP→MAC table."""
    console.print(f"\n[bold cyan][ SCANNER ][/bold cyan] Scanning [yellow]{subnet}[/yellow] …")
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            timeout=3, verbose=False
        )
    except Exception as e:
        console.print(f"[red]Scan error: {e}[/red]")
        return

    with lock:
        for _, rcv in ans:
            ip  = rcv[ARP].psrc
            mac = rcv[ARP].hwsrc.lower()
            ip_mac_table[ip] = mac
            console.print(f"  [green]✔[/green]  {ip:18s}  →  {mac}")

    console.print(f"[bold green]Trusted table built: {len(ip_mac_table)} hosts[/bold green]\n")


# ══════════════════════════════════════════════════════════
#  MODULE 2 – PACKET ANALYZER / DETECTOR
# ══════════════════════════════════════════════════════════
def analyze_packet(pkt):
    """Called for every captured ARP packet."""
    if not pkt.haslayer(ARP):
        return

    arp   = pkt[ARP]
    src_ip  = arp.psrc
    src_mac = arp.hwsrc.lower()
    dst_ip  = arp.pdst
    op      = arp.op   # 1=request  2=reply

    with lock:
        packet_stats["total"]   += 1
        packet_stats["requests" if op == 1 else "replies"] += 1

    # ── Flood detection ──────────────────────────────────
    now = time.time()
    with lock:
        flood_tracker[src_mac].append(now)
        flood_tracker[src_mac] = [t for t in flood_tracker[src_mac] if now - t < 1]
        count = len(flood_tracker[src_mac])

    if count >= ALERT_THRESHOLD:
        add_alert(
            "ARP FLOOD",
            src_ip, src_mac,
            f"ARP flood: {count} pkts/sec from {src_mac}",
            "red"
        )
        with lock:
            packet_stats["floods"] += 1
        return

    # ── Spoofing detection (IP→MAC mismatch) ─────────────
    with lock:
        known_mac = ip_mac_table.get(src_ip)

    if known_mac and known_mac != src_mac and not is_broadcast(src_mac):
        add_alert(
            "SPOOF DETECTED",
            src_ip, src_mac,
            f"IP {src_ip} claimed by {src_mac} but trusted MAC is {known_mac}",
            "bright_red"
        )
        with lock:
            packet_stats["spoofs"]   += 1
            ip_mac_table[src_ip]      = known_mac  # keep trusted entry

    # ── Gratuitous ARP (unsolicited reply) ────────────────
    elif op == 2 and src_ip == dst_ip:
        add_alert(
            "GRATUITOUS ARP",
            src_ip, src_mac,
            f"Gratuitous ARP from {src_ip} ({src_mac}) – possible cache poisoning probe",
            "yellow"
        )
        with lock:
            packet_stats["gratuitous"] += 1

    # ── New host – add to table ───────────────────────────
    else:
        with lock:
            if src_ip and src_ip not in ip_mac_table and not is_broadcast(src_mac):
                ip_mac_table[src_ip] = src_mac
                packet_stats["new_hosts"] += 1


# ══════════════════════════════════════════════════════════
#  MODULE 3 – LIVE MONITOR (sniff real packets)
# ══════════════════════════════════════════════════════════
def start_monitor(iface: str, duration: int):
    console.print(f"[bold cyan][ MONITOR ][/bold cyan] Sniffing ARP on [yellow]{iface}[/yellow] for [yellow]{duration}s[/yellow]\n")
    sniff(
        iface=iface,
        filter="arp",
        prn=analyze_packet,
        timeout=duration,
        store=False
    )


# ══════════════════════════════════════════════════════════
#  MODULE 4 – ATTACKER SIMULATOR
# ══════════════════════════════════════════════════════════
def simulate_attack(iface: str, target_ip: str, gateway_ip: str,
                    attack_type: str = "spoof", count: int = 10):
    """
    Simulate ARP attacks for testing the detector.
    attack_type: 'spoof' | 'gratuitous' | 'flood'
    Sends packets only on the local interface – lab use only.
    """
    console.print(Panel(
        f"[bold yellow]SIMULATION MODE[/bold yellow]\n"
        f"Type : [cyan]{attack_type.upper()}[/cyan]\n"
        f"Target  : [cyan]{target_ip}[/cyan]\n"
        f"Gateway : [cyan]{gateway_ip}[/cyan]\n"
        f"Packets : [cyan]{count}[/cyan]\n"
        f"Interface: [cyan]{iface}[/cyan]",
        title="⚠  ARP Attack Simulator",
        border_style="yellow"
    ))

    spoofed_mac = random_mac()
    console.print(f"[yellow]Using spoofed MAC: {spoofed_mac}[/yellow]\n")

    sent = 0
    for i in range(count):
        try:
            if attack_type == "spoof":
                # Poison target: tell target that gateway's MAC is spoofed_mac
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2,
                    psrc=gateway_ip,
                    hwsrc=spoofed_mac,
                    pdst=target_ip,
                    hwdst="ff:ff:ff:ff:ff:ff"
                )
                desc = f"Reply: {gateway_ip} is-at {spoofed_mac} → {target_ip}"

            elif attack_type == "gratuitous":
                # Gratuitous ARP broadcast
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2,
                    psrc=target_ip,
                    hwsrc=spoofed_mac,
                    pdst=target_ip,
                    hwdst="ff:ff:ff:ff:ff:ff"
                )
                desc = f"Gratuitous: {target_ip} is-at {spoofed_mac}"

            elif attack_type == "flood":
                # Rapid random ARP requests
                pkt = Ether(src=spoofed_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=1,
                    hwsrc=spoofed_mac,
                    psrc=f"10.0.0.{random.randint(1,254)}",
                    pdst=f"10.0.0.{random.randint(1,254)}"
                )
                desc = f"Flood pkt #{i+1} from {spoofed_mac}"
            else:
                console.print(f"[red]Unknown attack type: {attack_type}[/red]")
                return

            sendp(pkt, iface=iface, verbose=False)
            sent += 1
            console.print(f"  [yellow]→[/yellow] Sent #{i+1:03d}: {desc}")

            # Feed into analyzer so detector gets triggered
            analyze_packet(pkt)

            delay = 0.05 if attack_type == "flood" else 0.3
            time.sleep(delay)

        except Exception as e:
            console.print(f"  [red]Error sending packet #{i+1}: {e}[/red]")
            break

    console.print(f"\n[bold green]Simulation complete. {sent}/{count} packets sent.[/bold green]")


# ══════════════════════════════════════════════════════════
#  MODULE 5 – DEMO / DRY-RUN (no real packets)
# ══════════════════════════════════════════════════════════
def run_demo():
    """
    Fully offline demo: inject synthetic ARP events into the
    analyzer so you can see detection without root or a real NIC.
    """
    console.print(Panel(
        "[bold cyan]DEMO MODE[/bold cyan] – Synthetic ARP packets (no real NIC needed)",
        border_style="cyan"
    ))

    # Seed trusted table
    trusted = {
        "192.168.1.1":   "aa:bb:cc:11:22:33",
        "192.168.1.100": "de:ad:be:ef:00:01",
        "192.168.1.101": "de:ad:be:ef:00:02",
        "192.168.1.102": "de:ad:be:ef:00:03",
    }
    with lock:
        ip_mac_table.update(trusted)

    console.print("[green]Trusted table seeded:[/green]")
    for ip, mac in trusted.items():
        console.print(f"  {ip:18s} → {mac}")
    console.print()

    scenarios = [
        # (description, op, psrc, hwsrc, pdst)
        ("Normal request from known host",
         1, "192.168.1.100", "de:ad:be:ef:00:01", "192.168.1.1"),

        ("Normal reply – gateway",
         2, "192.168.1.1", "aa:bb:cc:11:22:33", "192.168.1.100"),

        ("🔴 SPOOF – attacker claims gateway IP with fake MAC",
         2, "192.168.1.1", "ba:d0:ca:fe:13:37", "192.168.1.100"),

        ("🟡 GRATUITOUS ARP from unknown host",
         2, "192.168.1.200", "ca:fe:ba:be:00:ff", "192.168.1.200"),

        ("🔴 SPOOF – attacker claims .100 with fake MAC",
         2, "192.168.1.100", "ee:ee:ee:ee:ee:ee", "192.168.1.1"),

        ("Normal – new host joins",
         1, "192.168.1.55", "11:22:33:44:55:66", "192.168.1.1"),
    ]

    for desc, op, psrc, hwsrc, pdst in scenarios:
        console.print(f"\n[bold]Injecting:[/bold] {desc}")
        # Build a fake packet-like object using Scapy
        pkt = Ether(src=hwsrc, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=op, psrc=psrc, hwsrc=hwsrc, pdst=pdst
        )
        analyze_packet(pkt)
        time.sleep(0.4)

    # Flood scenario
    console.print(f"\n[bold]Injecting:[/bold] 🔴 ARP FLOOD (10 rapid packets)")
    flood_mac = "ff:00:11:22:33:44"
    for i in range(10):
        pkt = Ether(src=flood_mac) / ARP(
            op=1, hwsrc=flood_mac,
            psrc=f"10.0.0.{i+1}", pdst="192.168.1.1"
        )
        analyze_packet(pkt)
        time.sleep(0.05)

    time.sleep(0.2)


# ══════════════════════════════════════════════════════════
#  REPORT RENDERER
# ══════════════════════════════════════════════════════════
def render_report():
    console.rule("[bold cyan]FINAL REPORT[/bold cyan]")

    # ── Stats ───────────────────────────────────────────
    stats_table = Table(title="Packet Statistics", box=box.ROUNDED, border_style="cyan")
    stats_table.add_column("Metric", style="bold white")
    stats_table.add_column("Count",  style="bold yellow", justify="right")

    with lock:
        stats = dict(packet_stats)

    for key, val in stats.items():
        color = "red" if key in ("spoofs", "floods") else "yellow" if key == "gratuitous" else "green"
        stats_table.add_row(key.replace("_", " ").title(), f"[{color}]{val}[/{color}]")
    console.print(stats_table)

    # ── Trusted IP→MAC Table ────────────────────────────
    ip_table = Table(title="Known IP → MAC Mapping", box=box.ROUNDED, border_style="green")
    ip_table.add_column("IP Address",  style="cyan")
    ip_table.add_column("MAC Address", style="green")

    with lock:
        for ip, mac in sorted(ip_mac_table.items()):
            ip_table.add_row(ip, mac)
    console.print(ip_table)

    # ── Alert Log ────────────────────────────────────────
    if alert_log:
        alert_table = Table(title="Alert Log", box=box.ROUNDED, border_style="red")
        alert_table.add_column("Time",    style="dim")
        alert_table.add_column("Type",    style="bold")
        alert_table.add_column("Src IP",  style="cyan")
        alert_table.add_column("Src MAC", style="magenta")
        alert_table.add_column("Details", style="white")

        with lock:
            for a in alert_log:
                alert_table.add_row(
                    a["time"],
                    f"[{a['color']}]{a['type']}[/{a['color']}]",
                    a["src_ip"],
                    a["src_mac"],
                    a["msg"]
                )
        console.print(alert_table)
    else:
        console.print("[bold green]✔  No anomalies detected.[/bold green]")

    console.rule()


# ══════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════
def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="ARP Guardian – Spoof Detection & Simulation",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--mode", choices=["monitor", "simulate", "demo", "scan"],
                        default="demo",
                        help=(
                            "monitor  – sniff live ARP packets and detect anomalies\n"
                            "simulate – send crafted ARP attack packets (lab only)\n"
                            "demo     – offline dry-run with synthetic packets\n"
                            "scan     – ARP-scan a subnet and build trusted table"
                        ))
    parser.add_argument("--iface",   default="eth0",        help="Network interface")
    parser.add_argument("--subnet",  default="192.168.1.0/24", help="Subnet to scan")
    parser.add_argument("--target",  default="192.168.1.100",  help="Target IP (simulate)")
    parser.add_argument("--gateway", default="192.168.1.1",    help="Gateway IP (simulate)")
    parser.add_argument("--attack",  default="spoof",
                        choices=["spoof", "gratuitous", "flood"],
                        help="Attack type for simulate mode")
    parser.add_argument("--count",   type=int, default=10, help="Packets to send (simulate)")
    parser.add_argument("--duration",type=int, default=30, help="Seconds to monitor")

    args = parser.parse_args()

    try:
        if args.mode == "demo":
            run_demo()

        elif args.mode == "scan":
            scan_network(args.subnet)

        elif args.mode == "monitor":
            # Optional pre-scan
            console.print("[dim]Tip: run --mode scan first to build a trusted table.[/dim]")
            t = threading.Thread(
                target=start_monitor,
                args=(args.iface, args.duration),
                daemon=True
            )
            t.start()
            t.join()

        elif args.mode == "simulate":
            simulate_attack(
                iface=args.iface,
                target_ip=args.target,
                gateway_ip=args.gateway,
                attack_type=args.attack,
                count=args.count
            )

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")

    finally:
        render_report()


if __name__ == "__main__":
    main()
