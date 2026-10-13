"""Nmap TCP connect scan wrapper. Only scan authorized targets."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def scan_target(target: str, output_path: str | Path, ports: str = "1-1024") -> Path:
    """Run Nmap service detection for the selected target and save XML internally."""
    target = (target or "").strip()
    if not target or target.startswith("-") or any(char.isspace() for char in target):
        raise ValueError("Enter a single IP address, CIDR network, or hostname.")
    if not shutil.which("nmap"):
        raise RuntimeError("Nmap is unavailable in the running environment. Rebuild/run the Docker image that installs Nmap.")

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    command = ["nmap", "-sT", "-sV", "-T3", "-p", ports, "-oX", str(output), target]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("The scan exceeded the 10-minute time limit. Try a single IP address.") from exc
    except subprocess.CalledProcessError as exc:
        details = (exc.stderr or exc.stdout or "Nmap returned an error.").strip()
        raise RuntimeError(details[-1500:]) from exc
    return output
