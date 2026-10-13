"""End-to-end XML parsing and risk scoring."""
from __future__ import annotations

from pathlib import Path
import pandas as pd

from fuzzynmap.fuzzy_engine import score_port
from fuzzynmap.xml_parser import parse_nmap_xml


def analyze_xml(xml_path: str | Path) -> pd.DataFrame:
    frame = parse_nmap_xml(xml_path)
    if frame.empty:
        frame["risk_score"] = pd.Series(dtype="float64")
        frame["risk_level"] = pd.Series(dtype="object")
        return frame
    frame["risk_score"] = frame.apply(
        lambda row: score_port(
            int(row["port"]), str(row["state"]), str(row["service"]),
            str(row["product"]), str(row["version"])
        ), axis=1
    )
    frame["risk_level"] = pd.cut(
        frame["risk_score"], bins=[-1, 34, 64, 100],
        labels=["Low", "Medium", "High"]
    ).astype(str)
    return frame
