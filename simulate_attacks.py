#!/usr/bin/env python3
"""Send harmless test probes to honeypot listeners on loopback only."""

import argparse
import asyncio
import base64
import ipaddress

import asyncssh

from honeypot import load_config


async def read_line(reader):
    return await asyncio.wait_for(reader.readline(), timeout=3)


async def probe_ssh(host, port, real_ssh=True):
    if real_ssh:
        async with await asyncssh.connect(
            host,
            port,
            username="sim-user",
            password="disposable-password",
            known_hosts=None,
            client_keys=[],
            agent_path=None,
            login_timeout=15,
        ) as connection:
            await connection.run("hostname", check=True, timeout=10)
        return

    reader, writer = await asyncio.open_connection(host, port)
    try:
        await read_line(reader)
        writer.write(b"simulator-client\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(64), timeout=3)
        writer.write(b"sim-user\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(64), timeout=3)
        writer.write(b"disposable-password\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(512), timeout=3)
    finally:
        writer.close()
        await writer.wait_closed()


async def probe_telnet(host, port):
    reader, writer = await asyncio.open_connection(host, port)
    await reader.read(256)
    writer.write(b"sim-user\r\ndisposable-password\r\n")
    await writer.drain()
    await reader.read(512)
    writer.close()
    await writer.wait_closed()


async def probe_ftp(host, port):
    reader, writer = await asyncio.open_connection(host, port)
    await read_line(reader)
    writer.write(b"USER sim-user\r\nPASS disposable-password\r\nQUIT\r\n")
    await writer.drain()
    await reader.read(512)
    writer.close()
    await writer.wait_closed()


async def probe_http(host, port):
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(b"GET /.env HTTP/1.1\r\nHost: localhost\r\nUser-Agent: local-simulator\r\nConnection: close\r\n\r\n")
    await writer.drain()
    await reader.read(2048)
    writer.close()
    await writer.wait_closed()


async def probe_mysql(host, port):
    reader, writer = await asyncio.open_connection(host, port)
    header = await reader.readexactly(4)
    await reader.readexactly(int.from_bytes(header[:3], "little"))
    payload = b"\x00" * 32 + b"sim-user\x00\x00mysql_native_password\x00"
    packet = len(payload).to_bytes(3, "little") + b"\x01" + payload
    writer.write(packet)
    await writer.drain()
    await reader.read(512)
    writer.close()
    await writer.wait_closed()


async def probe_redis(host, port):
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(b"*1\r\n$4\r\nPING\r\n*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")
    await writer.drain()
    await reader.read(1024)
    writer.close()
    await writer.wait_closed()


async def probe_smtp(host, port):
    reader, writer = await asyncio.open_connection(host, port)
    await read_line(reader)
    writer.write(b"EHLO local-simulator\r\n")
    await writer.drain()
    while True:
        response = await read_line(reader)
        if response.startswith(b"250 "):
            break
    writer.write(b"AUTH LOGIN\r\n")
    await writer.drain()
    await read_line(reader)
    writer.write(base64.b64encode(b"sim-user") + b"\r\n")
    await writer.drain()
    await read_line(reader)
    writer.write(base64.b64encode(b"disposable-password") + b"\r\n")
    await writer.drain()
    await read_line(reader)
    writer.write(b"QUIT\r\n")
    await writer.drain()
    await read_line(reader)
    writer.close()
    await writer.wait_closed()

async def probe_docker(host, port):
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(b"GET /_ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    await writer.drain()
    response = await asyncio.wait_for(reader.read(1024), timeout=3)
    if b"200 OK" not in response:
        raise OSError("Docker API probe received no success response")
    writer.close()
    await writer.wait_closed()


async def probe_kubernetes(host, port):
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(b"GET /version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    await writer.drain()
    response = await asyncio.wait_for(reader.read(2048), timeout=3)
    if b"gitVersion" not in response:
        raise OSError("Kubernetes API probe received no version response")
    writer.close()
    await writer.wait_closed()


async def probe_modbus(host, port):
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01")
    await writer.drain()
    header = await asyncio.wait_for(reader.readexactly(7), timeout=3)
    await reader.readexactly(int.from_bytes(header[4:6], "big") - 1)
    writer.close()
    await writer.wait_closed()


async def probe_mqtt(host, port):
    reader, writer = await asyncio.open_connection(host, port)
    connect_payload = b"\x00\x04MQTT\x04\x02\x00\x3c\x00\x03sim"
    writer.write(b"\x10" + bytes((len(connect_payload),)) + connect_payload)
    await writer.drain()
    if await asyncio.wait_for(reader.readexactly(4), timeout=3) != b"\x20\x02\x00\x00":
        raise OSError("MQTT broker rejected the simulated connection")
    writer.write(b"\xc0\x00")
    await writer.drain()
    if await asyncio.wait_for(reader.readexactly(2), timeout=3) != b"\xd0\x00":
        raise OSError("MQTT broker did not answer PINGREQ")
    writer.close()
    await writer.wait_closed()


PROBES = {
    "ssh": probe_ssh, "telnet": probe_telnet, "ftp": probe_ftp,
    "http": probe_http, "mysql": probe_mysql, "redis": probe_redis,
    "smtp": probe_smtp, "docker": probe_docker, "kubernetes": probe_kubernetes,
    "modbus": probe_modbus, "mqtt": probe_mqtt,
}
DEFAULT_PORTS = {"ssh": 2222, "telnet": 2323, "ftp": 2121, "http": 8080,
                 "mysql": 3306, "redis": 6379, "smtp": 2525,
                 "docker": 2375, "kubernetes": 6443, "modbus": 1502, "mqtt": 1883}


async def run(host, selected, ports, real_ssh=True):
    failures = []
    for name in selected:
        try:
            if name == "ssh":
                await PROBES[name](host, ports[name], real_ssh=real_ssh)
            else:
                await PROBES[name](host, ports[name])
            print(f"[+] {name.upper()} probe completed")
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
            failures.append(name)
            print(f"[-] {name.upper()} probe failed: {exc}")
    return not failures


def main():
    parser = argparse.ArgumentParser(description="Local-only honeypot test traffic generator")
    parser.add_argument("--host", default="127.0.0.1", help="Must be a loopback IP address")
    parser.add_argument("--services", nargs="+", choices=PROBES, default=list(PROBES))
    parser.add_argument("--config", help="Optional honeypot YAML/JSON config for service ports")
    args = parser.parse_args()
    try:
        address = ipaddress.ip_address(args.host)
    except ValueError:
        parser.error("--host must be a literal loopback IP address")
    if not address.is_loopback:
        parser.error("simulator refuses to connect to non-loopback hosts")
    ports = DEFAULT_PORTS
    real_ssh = True
    if args.config:
        try:
            config = load_config(args.config)
        except ValueError as exc:
            parser.error(str(exc))
        disabled = [name for name in args.services if not config["services"][name]["enabled"]]
        if disabled:
            parser.error(f"Requested service(s) disabled by config: {', '.join(disabled)}")
        ports = {name: service["port"] for name, service in config["services"].items()}
        real_ssh = config["services"]["ssh"]["real_ssh"]
    if not asyncio.run(run(args.host, args.services, ports, real_ssh)):
        raise SystemExit(1)


if __name__ == "__main__":
    main()