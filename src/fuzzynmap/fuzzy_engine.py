"""Explainable fuzzy inference for an educational port-risk score."""
from __future__ import annotations

import numpy as np
import skfuzzy as fuzz
from skfuzzy import control as ctrl


def _build_system():
    port = ctrl.Antecedent(np.arange(0, 65536, 1), "port")
    service_risk = ctrl.Antecedent(np.arange(0, 11, 1), "service_risk")
    state_open = ctrl.Antecedent(np.arange(0, 2, 1), "state_open")
    risk = ctrl.Consequent(np.arange(0, 101, 1), "risk")

    port["common"] = fuzz.trapmf(port.universe, [0, 0, 1024, 2000])
    port["registered"] = fuzz.trimf(port.universe, [1024, 5000, 10000])
    port["high"] = fuzz.trapmf(port.universe, [8000, 20000, 65535, 65535])

    service_risk["low"] = fuzz.trimf(service_risk.universe, [0, 0, 4])
    service_risk["medium"] = fuzz.trimf(service_risk.universe, [2, 5, 8])
    service_risk["high"] = fuzz.trimf(service_risk.universe, [6, 10, 10])

    state_open["closed"] = fuzz.trimf(state_open.universe, [0, 0, 0.5])
    state_open["open"] = fuzz.trimf(state_open.universe, [0.5, 1, 1])

    risk["low"] = fuzz.trimf(risk.universe, [0, 0, 35])
    risk["medium"] = fuzz.trimf(risk.universe, [20, 50, 75])
    risk["high"] = fuzz.trimf(risk.universe, [60, 100, 100])

    rules = [
        ctrl.Rule(state_open["closed"], risk["low"]),
        ctrl.Rule(state_open["open"] & service_risk["low"], risk["medium"]),
        ctrl.Rule(state_open["open"] & service_risk["medium"], risk["medium"]),
        ctrl.Rule(state_open["open"] & service_risk["high"], risk["high"]),
        ctrl.Rule(state_open["open"] & port["high"] & service_risk["low"], risk["medium"]),
    ]
    return ctrl.ControlSystem(rules)


def service_risk_level(service: str = "", product: str = "", version: str = "", port: int = 0) -> float:
    text = f"{service} {product} {version}".lower()
    score = 2.0
    risky_terms = ("telnet", "ftp", "rsh", "rlogin", "vnc", "smb", "microsoft-ds", "redis", "mongodb", "mysql", "postgres")
    if any(term in text for term in risky_terms):
        score += 4.0
    if any(term in text for term in ("ssl", "tls", "https", "ssh")):
        score -= 0.5
    if any(term in text for term in ("old", "outdated", "vulnerable")):
        score += 3.0
    if port in (21, 23, 445, 3389, 5900, 6379, 27017):
        score += 2.0
    return float(np.clip(score, 0, 10))


def score_port(port: int, state: str, service: str = "", product: str = "", version: str = "") -> float:
    """Return a 0–100 fuzzy score for one parsed port row."""
    is_open = 1.0 if str(state).lower() == "open" else 0.0
    service_level = service_risk_level(service, product, version, int(port))
    simulation = ctrl.ControlSystemSimulation(_build_system())
    simulation.input["port"] = float(np.clip(port, 0, 65535))
    simulation.input["service_risk"] = service_level
    simulation.input["state_open"] = is_open
    simulation.compute()
    return round(float(simulation.output["risk"]), 2)
