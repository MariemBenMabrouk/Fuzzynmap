"""Parse Nmap XML output into a pandas DataFrame."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
import pandas as pd


COLUMNS = ["host", "address", "port", "protocol", "state", "service", "product", "version", "extrainfo"]


def parse_nmap_xml(xml_path: str | Path) -> pd.DataFrame:
    path = Path(xml_path)
    if not path.exists():
        raise FileNotFoundError(path)
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise ValueError(f"Invalid Nmap XML: {exc}") from exc

    rows = []
    for host_node in root.findall("host"):
        address_node = host_node.find("address")
        address = address_node.get("addr", "") if address_node is not None else ""
        hostname_node = host_node.find("./hostnames/hostname")
        hostname = hostname_node.get("name", "") if hostname_node is not None else ""
        host = hostname or address or "unknown"
        for port_node in host_node.findall("./ports/port"):
            state_node = port_node.find("state")
            service_node = port_node.find("service")
            rows.append({
                "host": host,
                "address": address,
                "port": int(port_node.get("portid", "0")),
                "protocol": port_node.get("protocol", ""),
                "state": state_node.get("state", "unknown") if state_node is not None else "unknown",
                "service": service_node.get("name", "unknown") if service_node is not None else "unknown",
                "product": service_node.get("product", "") if service_node is not None else "",
                "version": service_node.get("version", "") if service_node is not None else "",
                "extrainfo": service_node.get("extrainfo", "") if service_node is not None else "",
            })
    return pd.DataFrame(rows, columns=COLUMNS)
