# Fuzzynmap

Fuzzynmap is a learning project that parses Nmap XML scan results and applies a transparent fuzzy-rule system to estimate a port/service risk score. It includes a Streamlit dashboard, sample scan data, tests, and a Docker setup.

## Project structure

```text
Fuzzynmap/
├── Dockerfile
├── .dockerignore
├── .gitignore
├── requirements.txt
├── README.md
├── src/
│   └── fuzzynmap/
│       ├── __init__.py
│       ├── scanner.py
│       ├── xml_parser.py
│       ├── fuzzy_engine.py
│       └── detector.py
├── dashboard/
│   └── app.py
├── data/
│   └── sample_scans/
│       └── sample_scan.xml
└── tests/
    ├── __init__.py
    ├── test_xml_parser.py
    └── test_fuzzy_engine.py
```

## Run with Docker

Install and start Docker Desktop with its WSL 2 integration enabled if you use Windows + Ubuntu WSL. Open a terminal in this project directory, then run:

```bash
docker build -t fuzzynmap .
docker run --rm -p 8501:8501 fuzzynmap
```

Open http://localhost:8501 in your browser.

## Run tests in Docker

```bash
docker run --rm fuzzynmap pytest -q
```

## Local development (optional)

Python 3.12 is recommended. Install Nmap separately if you want to run live scans.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=src pytest -q
streamlit run dashboard/app.py
```

## Live scanning

The scanner uses Nmap TCP connect scan (`-sT`) and XML output. Only scan systems you own or have explicit permission to assess. Live scanning is optional; the dashboard works with the included sample XML file.

## What the risk score means

The score is a heuristic educational indicator, not a guarantee that a host is vulnerable. The fuzzy rules use port number, service/version text, and Nmap state. Verify findings manually before making security decisions.
