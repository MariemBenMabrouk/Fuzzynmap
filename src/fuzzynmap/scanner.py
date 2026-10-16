"""Nmap TCP connect scanner. Only scan authorized targets."""
from __future__ import annotations

import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path


def scan_target(
    target: str,
    output_path: str | Path,
    ports: str = "1-10000",
) -> Path:
    """Scan one host or discover hosts in a CIDR network, then scan TCP ports."""
    target = (target or "").strip()

    if not target or target.startswith("-") or any(c.isspace() for c in target):
        raise ValueError("Enter one IP, CIDR network, or hostname.")

    if not shutil.which("nmap"):
        raise RuntimeError("Nmap is unavailable in this environment.")

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    discovery_xml = output.with_name("host_discovery.xml")

    try:
        try:
            network = ipaddress.ip_network(target, strict=False)
            is_network = "/" in target
        except ValueError:
            network = None
            is_network = False

        # Avoid accidentally scanning enormous networks.
        if is_network and network and network.num_addresses > 4096:
            raise ValueError("Network is too large. Use a CIDR with at most 4096 addresses.")

        hosts = [target]

        if is_network:
            # TCP discovery is more compatible with Docker Desktop than ARP discovery.
            discovery = [
                "nmap", "-n", "-PE", "-T4",
                "--max-retries", "1",
                "-oX", str(discovery_xml),
                target,
            ]

            try:
                subprocess.run(
                    discovery,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("Host discovery timed out after one minute.") from exc
            except subprocess.CalledProcessError as exc:
                details = (exc.stderr or exc.stdout or "Nmap discovery failed.").strip()
                raise RuntimeError(details[-1000:]) from exc

            root = ET.parse(discovery_xml).getroot()
            hosts = [
                address.get("addr")
                for node in root.findall("host")
                if node.find("status") is not None
                and node.find("status").get("state") == "up"
                for address in [node.find("address")]
                if address is not None and address.get("addrtype") in ("ipv4", "ipv6")
            ]

            if not hosts:
                raise RuntimeError(
                    "No hosts responded to TCP discovery. "
                    "Docker may not have a route to this LAN, or the hosts may block probes. "
                    "Verify the target subnet and Docker network connectivity."
                )

        command = [
            "nmap", "-n", "-Pn", "-sT", "-T4",
            "--open",
            "-p", ports,
            "-oX", str(output),
            *hosts,
        ]

        try:
            subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                timeout=180,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Port scan timed out after 3 minutes.") from exc
        except subprocess.CalledProcessError as exc:
            details = (exc.stderr or exc.stdout or "Nmap port scan failed.").strip()
            raise RuntimeError(details[-1000:]) from exc

        if not output.is_file() or output.stat().st_size == 0:
            raise RuntimeError("Nmap did not produce a valid XML result.")

        ET.parse(output)

    except ET.ParseError as exc:
        raise RuntimeError(f"Invalid Nmap XML: {exc}") from exc

    return output
