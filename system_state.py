"""
system_state.py — Realistic fake system state generator for honeypot.
Generates consistent but randomized system information per deployment.
"""

import math
import random
import secrets
import time
from datetime import datetime, timezone, timedelta
from typing import Dict


class SystemState:
    """Generates and maintains consistent fake system state per deployment."""

    _instance = None
    _initialized = False

    def __new__(cls, seed: str = None):
        if cls._instance is None or (
                seed is not None and getattr(cls._instance, "_seed", None) != seed):
            cls._instance = super().__new__(cls)
            cls._initialized = False
        return cls._instance

    def __init__(self, seed: str = None):
        if self._initialized:
            return
        self._initialized = True

        # Use seed for consistent per-deployment randomization
        if seed is None:
            seed = f"honeypot-{secrets.token_hex(4)}"
        self._seed = seed
        self._rng = random.Random(seed)
        self._boot_time = time.time() - self._rng.uniform(86400, 31536000)  # 1 day to 1 year ago
        self._started_monotonic = time.monotonic()

        # Generate consistent system identity
        self._generate_identity()
        self._generate_network()
        self._generate_filesystem()
        self._generate_processes()
        self._generate_users()
        self._generate_file_timestamps()

    def _generate_identity(self):
        """Generate consistent system identity."""
        distros = [
            ("Ubuntu", "22.04.3 LTS", "5.15.0-91-generic"),
            ("Ubuntu", "20.04.6 LTS", "5.15.0-91-generic"),
            ("Debian", "11.8", "5.10.0-21-amd64"),
            ("Debian", "12.2", "6.1.0-13-amd64"),
            ("CentOS", "7.9.2009", "3.10.0-1160.el7.x86_64"),
            ("Rocky Linux", "8.9", "4.18.0-513.5.1.el8_9.x86_64"),
            ("Alpine", "3.18.4", "6.1.55-0-virt"),
        ]
        distro = self._rng.choice(distros)

        hostnames = [
            "web-01", "web-02", "app-server", "db-primary", "cache-01",
            "worker-01", "worker-02", "api-gateway", "loadbalancer", "monitoring",
            "backup-01", "dev-server", "staging-01", "prod-01", "prod-02",
            "k8s-master-01", "k8s-worker-01", "k8s-worker-02", "rancher-01",
            "docker-host-01", "docker-host-02", "jenkins-01", "gitlab-01",
        ]

        self.identity = {
            "hostname": self._rng.choice(hostnames),
            "domain": self._rng.choice(["local", "internal", "corp", "lan", "datacenter"]),
            "distro_name": distro[0],
            "distro_version": distro[1],
            "kernel_version": distro[2],
            "architecture": "x86_64",
            "cpu_model": self._rng.choice([
                "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz",
                "Intel(R) Xeon(R) Silver 4214 CPU @ 2.20GHz",
                "AMD EPYC 7302P 16-Core Processor",
                "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz",
                "AMD Ryzen 9 5900X 12-Core Processor",
            ]),
            "cpu_cores": self._rng.choice([4, 8, 16, 24, 32]),
            "memory_gb": self._rng.choice([8, 16, 32, 64, 128]),
            "boot_time": self._boot_time,
        }
        self.identity["fqdn"] = f"{self.identity['hostname']}.{self.identity['domain']}"

    def _generate_network(self):
        """Generate consistent network interfaces."""
        # Primary interface
        primary_ip = f"10.{self._rng.randint(0, 255)}.{self._rng.randint(1, 254)}.{self._rng.randint(2, 254)}"
        secondary_ip = f"192.168.{self._rng.randint(1, 254)}.{self._rng.randint(2, 254)}"
        docker_ip = f"172.17.0.{self._rng.randint(2, 254)}"

        self.network = {
            "interfaces": [
                {
                    "name": "eth0",
                    "mac": self._random_mac(),
                    "ipv4": primary_ip,
                    "netmask": "255.255.255.0",
                    "gateway": f"10.{self._rng.randint(0, 255)}.{self._rng.randint(1, 254)}.1",
                    "mtu": 1500,
                    "flags": ["UP", "BROADCAST", "RUNNING", "MULTICAST"],
                },
                {
                    "name": "eth1",
                    "mac": self._random_mac(),
                    "ipv4": secondary_ip,
                    "netmask": "255.255.255.0",
                    "gateway": "",
                    "mtu": 1500,
                    "flags": ["UP", "BROADCAST", "RUNNING", "MULTICAST"],
                },
                {
                    "name": "docker0",
                    "mac": self._random_mac(),
                    "ipv4": docker_ip,
                    "netmask": "255.255.0.0",
                    "gateway": "",
                    "mtu": 1500,
                    "flags": ["UP", "BROADCAST", "RUNNING", "MULTICAST"],
                },
                {
                    "name": "lo",
                    "mac": "00:00:00:00:00:00",
                    "ipv4": "127.0.0.1",
                    "netmask": "255.0.0.0",
                    "gateway": "",
                    "mtu": 65536,
                    "flags": ["UP", "LOOPBACK", "RUNNING"],
                },
            ],
            "dns_servers": ["8.8.8.8", "8.8.4.4"],
            "search_domains": [self.identity["domain"]],
        }

    def _random_mac(self) -> str:
        """Generate a random MAC address."""
        return ":".join(f"{self._rng.randint(0, 255):02x}" for _ in range(6))

    def _generate_filesystem(self):
        """Generate consistent filesystem layout."""
        self.filesystem = {
            "mounts": [
                {"device": "/dev/sda1", "mount": "/", "fstype": "ext4", "size_gb": self._rng.choice([50, 100, 200, 500]), "used_gb": 0},
                {"device": "/dev/sda2", "mount": "/var", "fstype": "ext4", "size_gb": self._rng.choice([20, 50, 100]), "used_gb": 0},
                {"device": "/dev/sda3", "mount": "/home", "fstype": "ext4", "size_gb": self._rng.choice([100, 200, 500]), "used_gb": 0},
                {"device": "tmpfs", "mount": "/run", "fstype": "tmpfs", "size_gb": 2, "used_gb": 0},
                {"device": "tmpfs", "mount": "/tmp", "fstype": "tmpfs", "size_gb": 4, "used_gb": 0},
            ],
            "directories": {
                "/root": ["backup.tar.gz", "config.yml", "scripts", ".ssh", ".bash_history"],
                "/home": ["admin", "user", "deploy"],
                "/var": ["log", "www", "lib", "spool", "cache"],
                "/etc": ["nginx", "ssh", "docker", "kubernetes", "cron.d", "systemd"],
                "/opt": ["apps", "scripts", "monitoring"],
                "/usr": ["bin", "lib", "local", "share", "src"],
                "/tmp": ["session_abc123", "docker-build-456", "npm-789"],
                "/run": ["systemd", "docker.sock", "containerd.sock", "k3s"],
            },
            "key_files": {
                "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\nuser:x:1001:1001:user:/home/user:/bin/bash\n",
                "/etc/shadow": "root:$6$salt$hash:19000:0:99999:7:::\nadmin:$6$salt$hash:19000:0:99999:7:::\n",
                "/etc/ssh/sshd_config": "# SSH Config\nPort 22\nPermitRootLogin prohibit-password\nPubkeyAuthentication yes\n",
                "/etc/nginx/nginx.conf": "user www-data;\nworker_processes auto;\npid /run/nginx.pid;\n",
                "/root/.ssh/authorized_keys": "ssh-rsa AAAAB3NzaC1yc2E... admin@backup\n",
                "/home/admin/.bashrc": "# .bashrc\nalias ll='ls -la'\nexport PATH=$PATH:/opt/scripts\n",
                "/root/.aws/credentials": "[default]\naws_access_key_id = AKIA0000000000000000\naws_secret_access_key = example-not-a-real-secret\n",
                "/home/admin/.kube/config": "apiVersion: v1\nclusters:\n- cluster:\n    server: https://k8s.internal:6443\n  name: production\n",
            }
        }
        self.filesystem["directories"]["/root"].append(".aws")
        self.filesystem["directories"]["/root/.aws"] = ["credentials"]
        self.filesystem["directories"]["/home/admin"] = [".ssh", ".kube", ".bashrc", "deploy"]
        self.filesystem["directories"]["/home/admin/.aws"] = ["credentials"]
        self.filesystem["directories"]["/home/admin/.kube"] = ["config"]
        # Calculate used space
        for mount in self.filesystem["mounts"]:
            mount["used_gb"] = self._rng.randint(int(mount["size_gb"] * 0.1), int(mount["size_gb"] * 0.7))

    def _generate_processes(self):
        """Generate realistic process list."""
        boot_date = datetime.fromtimestamp(self._boot_time, timezone.utc)
        boot_label = boot_date.strftime("%b %d")
        base_processes = [
            {"pid": 1, "ppid": 0, "user": "root", "cmd": "/sbin/init", "cpu": 0.0, "mem": 0.1, "start": boot_label},
            {"pid": 2, "ppid": 0, "user": "root", "cmd": "[kthreadd]", "cpu": 0.0, "mem": 0.0, "start": boot_label},
            {"pid": 3, "ppid": 2, "user": "root", "cmd": "[rcu_gp]", "cpu": 0.0, "mem": 0.0, "start": boot_label},
            {"pid": 100, "ppid": 1, "user": "root", "cmd": "/lib/systemd/systemd-journald", "cpu": 0.1, "mem": 0.5, "start": boot_label},
            {"pid": 101, "ppid": 1, "user": "root", "cmd": "/lib/systemd/systemd-udevd", "cpu": 0.0, "mem": 0.3, "start": boot_label},
            {"pid": 500, "ppid": 1, "user": "root", "cmd": "/usr/sbin/sshd -D", "cpu": 0.0, "mem": 1.2, "start": boot_label},
            {"pid": 501, "ppid": 1, "user": "root", "cmd": "/usr/sbin/cron -f", "cpu": 0.0, "mem": 0.5, "start": boot_label},
            {"pid": 502, "ppid": 1, "user": "root", "cmd": "/usr/bin/dockerd -H fd://", "cpu": 0.2, "mem": 2.5, "start": boot_label},
            {"pid": 503, "ppid": 1, "user": "root", "cmd": "/usr/bin/containerd", "cpu": 0.1, "mem": 1.8, "start": boot_label},
            {"pid": 504, "ppid": 1, "user": "root", "cmd": "/usr/sbin/nginx -g 'daemon off;'", "cpu": 0.1, "mem": 3.2, "start": boot_label},
            {"pid": 505, "ppid": 504, "user": "www-data", "cmd": "nginx: worker process", "cpu": 0.2, "mem": 2.1, "start": boot_label},
            {"pid": 506, "ppid": 504, "user": "www-data", "cmd": "nginx: worker process", "cpu": 0.1, "mem": 2.0, "start": boot_label},
            {"pid": 600, "ppid": 502, "user": "root", "cmd": "/pause", "cpu": 0.0, "mem": 0.1, "start": boot_label},
            {"pid": 601, "ppid": 502, "user": "root", "cmd": "nginx -g 'daemon off;'", "cpu": 0.1, "mem": 1.5, "start": boot_label},
            {"pid": 602, "ppid": 502, "user": "root", "cmd": "redis-server *:6379", "cpu": 0.1, "mem": 2.2, "start": boot_label},
            {"pid": 603, "ppid": 502, "user": "root", "cmd": "postgres -D /var/lib/postgresql/data", "cpu": 0.3, "mem": 8.5, "start": boot_label},
        ]

        # Add some dynamic processes
        for i in range(self._rng.randint(5, 15)):
            base_processes.append({
                "pid": 1000 + i,
                "ppid": self._rng.choice([1, 500, 502]),
                "user": self._rng.choice(["root", "www-data", "postgres", "redis", "admin"]),
                "cmd": self._rng.choice([
                    "python3 /opt/app/main.py",
                    "java -jar /opt/app.jar",
                    "node /opt/server.js",
                    "go run /opt/service/main.go",
                    "/opt/scripts/backup.sh",
                    "rsync -av /data/ /backup/",
                    "mysqldump --all-databases",
                    "kubectl get pods -A",
                ]),
                "cpu": round(self._rng.uniform(0.0, 2.0), 1),
                "mem": round(self._rng.uniform(0.5, 10.0), 1),
                "start": self._random_recent_date(),
            })

        self.processes = base_processes

    def _random_recent_date(self) -> str:
        """Generate a recent date string."""
        days_ago = self._rng.randint(0, 30)
        date = datetime.fromtimestamp(self._boot_time, timezone.utc) - timedelta(days=days_ago)
        return date.strftime("%b %d")

    def _generate_users(self):
        """Generate user accounts."""
        self.users = [
            {"username": "root", "uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash", "last_login": self._random_recent_login()},
            {"username": "admin", "uid": 1000, "gid": 1000, "home": "/home/admin", "shell": "/bin/bash", "last_login": self._random_recent_login()},
            {"username": "user", "uid": 1001, "gid": 1001, "home": "/home/user", "shell": "/bin/bash", "last_login": self._random_recent_login()},
            {"username": "deploy", "uid": 1002, "gid": 1002, "home": "/home/deploy", "shell": "/bin/bash", "last_login": self._random_recent_login()},
            {"username": "www-data", "uid": 33, "gid": 33, "home": "/var/www", "shell": "/usr/sbin/nologin", "last_login": None},
            {"username": "postgres", "uid": 999, "gid": 999, "home": "/var/lib/postgresql", "shell": "/bin/bash", "last_login": None},
            {"username": "redis", "uid": 100, "gid": 101, "home": "/var/lib/redis", "shell": "/usr/sbin/nologin", "last_login": None},
            {"username": "docker", "uid": 998, "gid": 998, "home": "/home/docker", "shell": "/bin/bash", "last_login": None},
        ]

    def _random_recent_login(self) -> str:
        """Generate a recent login timestamp."""
        hours_ago = self._rng.randint(1, 720)
        dt = datetime.fromtimestamp(self._boot_time, timezone.utc) - timedelta(hours=hours_ago)
        return dt.strftime("%a %b %d %H:%M:%S %Y")

    def _generate_file_timestamps(self):
        """Assign deployment-consistent timestamps to files in the fake filesystem."""
        now = time.time()
        paths = set(self.filesystem["key_files"])
        for directory, names in self.filesystem["directories"].items():
            paths.update(f"{directory.rstrip('/')}/{name}" for name in names)
        self.file_mtimes = {
            path: now - self._rng.uniform(3600, max(3600, self.uptime_seconds()))
            for path in paths
        }

    def file_timestamp(self, path: str) -> datetime:
        """Return a plausible synthetic mtime for a virtual file or directory."""
        timestamp = self.file_mtimes.get(path)
        if timestamp is None:
            timestamp = self._boot_time + self._rng.uniform(0, self.uptime_seconds())
            self.file_mtimes[path] = timestamp
        return datetime.fromtimestamp(timestamp, timezone.utc)

    def mark_file_modified(self, path: str, timestamp: float = None) -> None:
        """Update only the virtual timestamp; no host filesystem is accessed."""
        self.file_mtimes[path] = time.time() if timestamp is None else timestamp

    def get_processes(self) -> list:
        """Return a changing view of the deployment's fictional process table."""
        elapsed = time.monotonic()
        processes = []
        for process in self.processes:
            item = dict(process)
            phase = elapsed / 17 + item["pid"]
            item["cpu"] = round(max(0.0, item["cpu"] + 0.15 * math.sin(phase)), 1)
            item["mem"] = round(max(0.1, item["mem"] + 0.2 * math.sin(phase / 3)), 1)
            processes.append(item)
        return processes

    def get_interface_counters(self, interface: str) -> tuple[int, int, int, int]:
        """Return synthetic RX/TX packet and byte counters that increase over time."""
        elapsed = max(0, int(time.monotonic() - self._started_monotonic))
        offset = sum(ord(char) for char in interface) * 97
        rx_packets = offset + elapsed * 3
        tx_packets = offset + elapsed * 2
        return rx_packets, rx_packets * 128, tx_packets, tx_packets * 196

    def uptime_string(self) -> str:
        """Get formatted uptime string."""
        uptime_seconds = time.time() - self._boot_time
        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        if days > 0:
            return f"{days} days, {hours}:{minutes:02d}"
        return f"{hours}:{minutes:02d}"

    def uptime_seconds(self) -> float:
        """Get uptime in seconds."""
        return time.time() - self._boot_time

    def get_load_average(self) -> tuple:
        """Get realistic load average."""
        base = self.identity["cpu_cores"] * 0.1
        phase = time.monotonic() / 45
        return (
            round(max(0.0, base + 0.25 * math.sin(phase)), 2),
            round(max(0.0, base + 0.2 * math.sin(phase / 5)), 2),
            round(max(0.0, base + 0.15 * math.sin(phase / 15)), 2),
        )

    def get_memory_info(self) -> Dict[str, int]:
        """Get memory info in KB."""
        total_kb = self.identity["memory_gb"] * 1024 * 1024
        used_fraction = 0.5 + 0.03 * math.sin(time.monotonic() / 90)
        used_kb = int(total_kb * used_fraction)
        return {
            "total": total_kb,
            "used": used_kb,
            "free": total_kb - used_kb,
            "available": total_kb - int(used_kb * 0.6),
            "buffers": int(total_kb * 0.02),
            "cached": int(total_kb * 0.15),
        }

    def get_disk_usage(self, path: str = "/") -> Dict[str, int]:
        """Get disk usage for a path in KB."""
        for mount in self.filesystem["mounts"]:
            if path.startswith(mount["mount"]):
                total = mount["size_gb"] * 1024 * 1024
                used = mount["used_gb"] * 1024 * 1024
                return {"total": int(total), "used": int(used), "free": int(total - used)}
        return {"total": 0, "used": 0, "free": 0}


# Global instance getter
def get_system_state(seed: str = None) -> SystemState:
    """Get the singleton SystemState instance."""
    return SystemState(seed)


def reset_system_state(seed: str = None):
    """Reset the system state (for testing)."""
    SystemState._instance = None
    SystemState._initialized = False
    return SystemState(seed)