from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fuzzynmap.fuzzy_engine import score_port


def test_score_is_in_range():
    score = score_port(21, "open", "ftp", "vsftpd", "3.0.3")
    assert 0 <= score <= 100


def test_closed_port_is_low_risk():
    score = score_port(3306, "closed", "mysql", "", "")
    assert score < 40


def test_open_registered_port_has_score():
    score = score_port(8080, "open", "http", "", "")
    assert 0 <= score <= 100
