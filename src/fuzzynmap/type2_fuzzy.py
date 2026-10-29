
"""Interval Type-2 Mamdani fuzzy engine for Fuzzynmap."""

from functools import lru_cache

import numpy as np
from pyit2fls import (
    IT2FS_Gaussian_UncertStd,
    IT2Mamdani,
    min_t_norm,
    max_s_norm,
)


def _it2_gaussian(domain, mean, sigma, uncertainty):
    """Create an interval Type-2 Gaussian fuzzy set."""
    return IT2FS_Gaussian_UncertStd(
        domain,
        [mean, sigma, uncertainty, 1.0],
    )


@lru_cache(maxsize=1)
def _build_type2_system():
    """Build and cache the Interval Type-2 Mamdani system."""

    port_u = np.linspace(0, 65535, 301)
    service_u = np.linspace(0, 10, 101)
    state_u = np.linspace(0, 1, 101)
    known_u = np.linspace(0, 1, 101)
    risk_u = np.linspace(0, 100, 201)

    # Port membership functions
    port_common = _it2_gaussian(port_u, 512, 700, 150)
    port_registered = _it2_gaussian(port_u, 5000, 2500, 500)
    port_high = _it2_gaussian(port_u, 30000, 20000, 4000)

    # Service severity membership functions
    service_low = _it2_gaussian(service_u, 1.5, 1.5, 0.3)
    service_medium = _it2_gaussian(service_u, 5, 1.5, 0.3)
    service_high = _it2_gaussian(service_u, 8.5, 1.5, 0.3)

    # Port state
    state_closed = _it2_gaussian(state_u, 0, 0.25, 0.04)
    state_open = _it2_gaussian(state_u, 1, 0.25, 0.04)

    # Service identification
    service_unknown = _it2_gaussian(known_u, 0, 0.25, 0.04)
    service_known = _it2_gaussian(known_u, 1, 0.25, 0.04)

    # Risk output sets
    risk_low = _it2_gaussian(risk_u, 15, 15, 3)
    risk_medium = _it2_gaussian(risk_u, 50, 15, 3)
    risk_high = _it2_gaussian(risk_u, 85, 15, 3)

    # Genuine Interval Type-2 Mamdani system.
    # Centroid type reduction uses the selected KM algorithm.
    system = IT2Mamdani(
        min_t_norm,
        max_s_norm,
        method="Centroid",
        algorithm="KM",
    )

    for name in (
        "port",
        "service_risk",
        "state_open",
        "service_known",
    ):
        system.add_input_variable(name)

    system.add_output_variable("risk")

    # Closed ports: low risk
    system.add_rule(
        [("state_open", state_closed)],
        [("risk", risk_low)],
    )

    # Open ports: severity-based rules
    system.add_rule(
        [
            ("state_open", state_open),
            ("service_risk", service_low),
        ],
        [("risk", risk_medium)],
    )

    system.add_rule(
        [
            ("state_open", state_open),
            ("service_risk", service_medium),
        ],
        [("risk", risk_medium)],
    )

    system.add_rule(
        [
            ("state_open", state_open),
            ("service_risk", service_high),
        ],
        [("risk", risk_high)],
    )

    # High-numbered open port with low service severity
    system.add_rule(
        [
            ("state_open", state_open),
            ("port", port_high),
            ("service_risk", service_low),
        ],
        [("risk", risk_medium)],
    )

    # An unknown service receives a medium-risk assessment
    system.add_rule(
        [
            ("state_open", state_open),
            ("service_known", service_unknown),
        ],
        [("risk", risk_medium)],
    )

    return system


def _service_risk_level(
    service="",
    product="",
    version="",
    port=0,
):
    """Estimate service severity on a 0–10 scale."""
    text = f"{service} {product} {version}".lower()

    if "tcpwrapped" in text or not text.strip():
        return 3.0

    score = 2.0

    risky_terms = (
        "telnet", "ftp", "rsh", "rlogin", "vnc",
        "smb", "microsoft-ds", "redis", "mongodb",
        "mysql", "postgres",
    )

    if any(term in text for term in risky_terms):
        score += 4.0

    if any(term in text for term in ("ssl", "tls", "https", "ssh")):
        score -= 0.5

    if any(term in text for term in ("old", "outdated", "vulnerable")):
        score += 3.0

    if int(port) in (21, 23, 445, 3389, 5900, 6379, 27017):
        score += 2.0

    return float(np.clip(score, 0, 10))


def score_port_interval(
    port: int,
    state: str,
    service: str = "",
    product: str = "",
    version: str = "",
) -> tuple[float, float]:
    """Return the lower and upper type-reduced risk bounds."""

    port = int(np.clip(int(port), 0, 65535))
    state_value = 1.0 if str(state).lower() == "open" else 0.0

    service_text = f"{service} {product} {version}".lower()
    known_value = (
        0.0
        if "tcpwrapped" in service_text or not service_text.strip()
        else 1.0
    )

    severity = _service_risk_level(
        service=service,
        product=product,
        version=version,
        port=port,
    )

    inputs = {
        "port": float(port),
        "service_risk": severity,
        "state_open": state_value,
        "service_known": known_value,
    }

    result = _build_type2_system().evaluate(inputs)

    # Centroid evaluation returns the type-reduced output as
    # the second element: a mapping from output name to interval.
    if not isinstance(result, tuple) or len(result) != 2:
        raise RuntimeError(
            "Unexpected pyit2fls evaluation result format."
        )

    type_reduced = result[1]
    interval = type_reduced["risk"]

    lower, upper = map(float, interval)

    lower = float(np.clip(lower, 0, 100))
    upper = float(np.clip(upper, 0, 100))

    if lower > upper:
        raise RuntimeError(
            f"Invalid type-reduced interval: {lower}, {upper}"
        )

    return round(lower, 2), round(upper, 2)
