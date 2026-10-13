from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fuzzynmap.xml_parser import parse_nmap_xml


def test_sample_xml_parses_expected_ports():
    result = parse_nmap_xml(ROOT / "data" / "sample_scans" / "sample_scan.xml")
    assert len(result) == 6
    assert 21 in result["port"].tolist()
    assert "open" in result["state"].tolist()
    assert "example-lab.local" in result["host"].tolist()
