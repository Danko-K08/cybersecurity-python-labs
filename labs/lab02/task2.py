import re
import csv
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass
class ArpConflict:
    mac: str
    ips: list[str]

def setup_logger(log_file: str):
    logger = logging.getLogger("ARP_Auditor")
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(log_file) if log_file else logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    if not logger.handlers:
        logger.addHandler(handler)
    return logger

def analyze_arp(arp_file: str, output_json: str, detect_spoofing: bool, log_file: str):
    logger = setup_logger(log_file)
    logger.info(f"Parsing ARP table snapshot from {arp_file}...")

    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    mac_pattern = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")

    mac_to_ips = defaultdict(list)
    valid_count = 0
    invalid_count = 0

    try:
        with open(arp_file, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get("IP Address", "").strip()
                mac = row.get("MAC Address", "").strip().lower()

                if ip_pattern.match(ip) and mac_pattern.match(mac):
                    if ip not in mac_to_ips[mac]:
                        mac_to_ips[mac].append(ip)
                    valid_count += 1
                else:
                    invalid_count += 1
    except FileNotFoundError:
        logger.error(f"Файл {arp_file} не знайдено.")
        return

    logger.info(f"Validated {valid_count} IP/MAC entries.")
    print("=== Validated Entries Summary ===")
    print(f"Valid IP/MAC Pairs: {valid_count}")
    print(f"Invalid Syntax    : {invalid_count}\n")

    conflicts = []
    if detect_spoofing:
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                conflicts.append(ArpConflict(mac=mac, ips=ips))

    if conflicts:
        print("=== CRITICAL SECURITY ALERTS: ARP-SPOOFING DETECTED ===")
        for conflict in conflicts:
            print("[ALERT] MAC Address Duplicate Conflict!")
            print(f"MAC Address: {conflict.mac} associated with MULTIPLE IP addresses:")
            for ip in conflict.ips:
                print(f"  - {ip}")
            print("-> POSSIBLE MAN-IN-THE-MIDDLE / ARP-SPOOFING ATTACK IN PROGRESS!\n")
            logger.warning(f"ARP-SPOOFING DETECTED: MAC {conflict.mac} with IPs {conflict.ips}")

    if output_json:
        out_path = Path(output_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump([asdict(c) for c in conflicts], f, indent=4)
        logger.info(f"Critical conflict logged to {output_json}")