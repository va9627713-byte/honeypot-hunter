#!/usr/bin/env python3
"""Check which ports are available for honeypot services."""

import argparse
import socket
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None


DEFAULT_PORTS = {
    "ssh": 2222,
    "telnet": 2323,
    "ftp": 2121,
    "http": 8080,
    "mysql": 3306,
    "redis": 6379,
    "smtp": 2525,
    "docker": 2375,
    "kubernetes": 6443,
    "modbus": 1502,
    "mqtt": 1883,
}


def check_port(host: str, port: int) -> tuple[bool, str]:
    """Check if a port is available."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            result = s.connect_ex((host, port))
            if result == 0:
                return False, "in use"
            return True, "available"
    except Exception as e:
        return False, f"error: {e}"


def load_config_ports(config_path: str) -> dict:
    """Load ports from config file."""
    if not yaml:
        print("PyYAML not installed, using defaults")
        return DEFAULT_PORTS

    path = Path(config_path)
    if not path.exists():
        print(f"Config file not found: {config_path}")
        return DEFAULT_PORTS

    with open(path) as f:
        config = yaml.safe_load(f) or {}

    ports = {}
    services = config.get("services", {})
    for name, svc in services.items():
        if svc.get("enabled", True):
            ports[name] = svc.get("port", DEFAULT_PORTS.get(name, 0))
    return ports


def main():
    parser = argparse.ArgumentParser(description="Check honeypot service ports")
    parser.add_argument("--host", default="127.0.0.1", help="Host to check")
    parser.add_argument("--config", help="Config file to read ports from")
    parser.add_argument("--services", nargs="+", help="Specific services to check")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    ports = DEFAULT_PORTS
    if args.config:
        ports = load_config_ports(args.config)

    if args.services:
        ports = {k: v for k, v in ports.items() if k in args.services}

    results = {}
    for name, port in sorted(ports.items()):
        available, status = check_port(args.host, port)
        results[name] = {
            "port": port,
            "available": available,
            "status": status,
        }
        if not args.json:
            status_icon = "✓" if available else "✗"
            print(f"  {status_icon} {name:12} port {port:5} : {status}")

    if args.json:
        import json
        print(json.dumps(results, indent=2))

    # Exit code: 0 if all available, 1 if any in use
    if not all(r["available"] for r in results.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()