#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import socket
import subprocess
import sys
import os
from typing import List, Tuple

try:
    from scapy.all import ARP, Ether, srp, conf  # type: ignore
except Exception as e:
    print("[!] Failed to import scapy. On Kali run: sudo apt-get install python3-scapy")
    print("    Error:", e)
    sys.exit(1)


def require_root():
    if os.geteuid() != 0:
        print("[!] Please run as root: sudo python3 lan_scanner.py ...")
        sys.exit(1)


def autodetect_cidr() -> str:
    """
    Return the first global IPv4 address in CIDR form (e.g., '192.168.1.23/24')
    """
    try:
        out = subprocess.check_output(
            ["bash", "-lc", "ip -o -4 addr show up primary scope global | awk '{print $4}' | head -n1"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        if out:
            return out
    except Exception:
        pass

    try:
        gw, intf, _ = conf.route.route("0.0.0.0")
        ip = conf.ifaces[intf].ip
        nm = conf.ifaces[intf].netmask
        if ip and nm:
            prefix = ipaddress.IPv4Network(f"0.0.0.0/{nm}").prefixlen
            return f"{ip}/{prefix}"
    except Exception:
        pass

    raise RuntimeError("Could not auto-detect local IPv4 CIDR. Please provide --subnet x.x.x.x/yy")


def cidr_to_network(cidr: str) -> str:
    net = ipaddress.ip_network(cidr, strict=False)
    return str(net)


def reverse_dns(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return ""


def scan_network(target_cidr: str) -> List[Tuple[str, str, str]]:
    """
    Returns list of tuples: (ip, mac, hostname)
    """
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_cidr)
    answered, _ = srp(packet, timeout=2, retry=1, verbose=False)
    results = []
    for _, recv in answered:
        ip = recv.psrc
        mac = recv.hwsrc
        host = reverse_dns(ip)
        results.append((ip, mac, host))
    results.sort(key=lambda x: tuple(map(int, x[0].split("."))))
    return results


def print_table(rows: List[Tuple[str, str, str]]):
    if not rows:
        print("[i] No devices found. Try widening the subnet or ensuring you are connected.")
        return
    headers = ("IP Address", "MAC Address", "Hostname")
    widths = [len(h) for h in headers]
    for ip, mac, host in rows:
        widths[0] = max(widths[0], len(ip))
        widths[1] = max(widths[1], len(mac))
        widths[2] = max(widths[2], len(host))

    def sep():
        print("+-" + "-+-".join("-" * w for w in widths) + "-+")

    sep()
    print("| " + " | ".join(h.ljust(w) for h, w in zip(headers, widths)) + " |")
    sep()
    for ip, mac, host in rows:
        print("| " + " | ".join(val.ljust(w) for val, w in zip((ip, mac, host), widths)) + " |")
    sep()


def save_csv(rows: List[Tuple[str, str, str]], path: str):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "mac", "hostname"])
        writer.writerows(rows)
    print(f"[✓] Saved CSV to: {path}")


def main():
    parser = argparse.ArgumentParser(description="Simple LAN device scanner (ARP)")
    parser.add_argument("--subnet", help="Target subnet in CIDR (e.g. 192.168.1.0/24). If omitted, auto-detect.")
    parser.add_argument("--csv", help="Save results to CSV file")
    args = parser.parse_args()

    require_root()

    try:
        cidr = args.subnet if args.subnet else autodetect_cidr()
        network = cidr_to_network(cidr)
    except Exception as e:
        print(f"[!] {e}")
        sys.exit(1)

    print(f"[i] Scanning subnet: {network}")
    rows = scan_network(network)
    print_table(rows)
    if args.csv:
        save_csv(rows, args.csv)


if __name__ == "__main__":
    main()
