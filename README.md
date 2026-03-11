# Netdia

Local-first homelab network discovery and diagramming. Netdia scans your subnets with nmap, probes HTTP/TLS services for metadata, optionally imports reverse-proxy sites from OPNsense/Caddy, and renders everything as an interactive draw.io-style flowchart in the browser.

![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

## Features

- **Subnet scanning** — Discovers active hosts and open TCP ports via nmap (`--top-ports 1000`, parallel per-host scans)
- **Service enrichment** — Probes HTTP/HTTPS endpoints for page titles, server headers, TLS SANs, and favicons
- **OPNsense/Caddy integration** — Imports reverse-proxy domain mappings with upstream targets from the Caddy plugin API
- **Flowchart topology** — Interactive top-down diagram: Internet → Firewall → Subnets → Hosts → Websites, with SVG connection lines
- **Live scan progress** — Real-time stage updates, per-host nmap progress, and event log streaming
- **Detail panel** — Click any host to see services, websites, TLS names, and upstream targets with icons
- **Scan cancellation** — Gracefully stops nmap processes mid-scan
- **SQLite storage** — WAL-mode database with full scan history, no external DB required
- **Customization** — Override display names, icons, and categories for any host or service

## Requirements

- Python 3.12 or newer
- `nmap` available on `PATH`

### Installing nmap

```bash
# macOS
brew install nmap

# Debian / Ubuntu
sudo apt install nmap

# Arch
sudo pacman -S nmap
```

## Quick Start

```bash
git clone https://github.com/brennonoverton/netdia.git
cd netdia
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
netdia serve
```

Open [http://localhost:8765](http://localhost:8765) in your browser.

### First scan

1. Enter a CIDR block (e.g., `192.168.1.0/24`) in the **Targets** panel and click **Add**
2. Click **Run Scan**
3. Watch the live progress — host discovery, per-host port scans, HTTP probing
4. When complete, the topology flowchart renders with all discovered hosts, services, and websites

## CLI

```
netdia serve [--host HOST] [--port PORT]
```

Starts the web server. Default: `127.0.0.1:8765`.

```
netdia scan [CIDR ...]
```

Runs a headless scan and prints a JSON summary. Uses enabled targets from the database if no CIDRs are given.

## Configuration

All settings are read from environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `NETDIA_DB_PATH` | `.netdia/netdia.db` | SQLite database path |
| `NETDIA_DATA_DIR` | `.netdia` | Data directory |
| `NETDIA_OPNSENSE_URL` | *(empty)* | OPNsense base URL (e.g., `https://192.168.1.1:8443`) |
| `NETDIA_OPNSENSE_KEY` | *(empty)* | OPNsense API key |
| `NETDIA_OPNSENSE_SECRET` | *(empty)* | OPNsense API secret |
| `NETDIA_OPNSENSE_VERIFY_SSL` | `true` | Set to `false` for self-signed certs |

### OPNsense / Caddy Setup

1. In OPNsense, go to **System → Access → Users** and create or edit an API user
2. Generate an API key+secret pair and download the key file
3. Under **System → Access → Groups**, ensure the user's group has **Caddy: Normal** permissions
4. Set the environment variables:

```bash
export NETDIA_OPNSENSE_URL=https://192.168.1.1:8443
export NETDIA_OPNSENSE_KEY=your-api-key
export NETDIA_OPNSENSE_SECRET=your-api-secret
export NETDIA_OPNSENSE_VERIFY_SSL=false  # if using self-signed certs
```

Netdia will import all Caddy reverse-proxy domains, match them to scanned hosts via upstream IP:port, and probe each domain for page titles and favicons.

## Architecture

```
src/netdia/
├── app.py              # FastAPI application and REST API routes
├── cli.py              # CLI entry point (serve / scan commands)
├── config.py           # Environment-based settings loader
├── database.py         # SQLite schema, CRUD, topology builder
├── models.py           # Dataclasses (hosts, services, websites, scans)
├── classification.py   # Host/service categorization, icons, colors
├── enrichment.py       # HTTP/TLS probing, favicon extraction, reverse DNS
├── nmap_runner.py      # Nmap subprocess wrapper with progress streaming
├── scan_service.py     # ScanManager — orchestrates the full pipeline
├── opnsense.py         # OPNsense Caddy API client
└── static/
    ├── index.html      # Single-page application shell
    ├── app.js          # Frontend: topology rendering, scan polling, detail views
    └── styles.css      # Dark theme, flowchart layout, responsive design
```

### Scan Pipeline

1. **Host discovery** — `nmap -sn` across all target CIDRs
2. **Port scanning** — Parallel per-host scans (`--top-ports 1000 -sV -T4`) with up to 5 workers
3. **Service enrichment** — HTTP/HTTPS probes for titles, headers, TLS SANs on web ports
4. **OPNsense import** — Fetch Caddy reverse-proxy config, filter to scanned subnets, probe domains
5. **Topology build** — Group hosts by /24 subnet, associate websites to hosts via service IDs

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/targets` | List scan targets |
| `POST` | `/api/targets` | Add a CIDR target |
| `PATCH` | `/api/targets/{id}` | Enable/disable a target |
| `POST` | `/api/scans` | Start a new scan |
| `GET` | `/api/scans/latest` | Latest scan status |
| `GET` | `/api/scans/{id}` | Scan status by ID |
| `POST` | `/api/scans/{id}/cancel` | Cancel a running scan |
| `GET` | `/api/scans/{id}/events` | Scan event log |
| `GET` | `/api/topology/latest` | Full topology (subnets, hosts, services, websites) |
| `GET` | `/api/hosts/{id}` | Host detail with services and websites |
| `PATCH` | `/api/hosts/{id}/overrides` | Customize host display |
| `PATCH` | `/api/services/{id}/overrides` | Customize service display |
| `GET` | `/api/websites` | All websites from latest scan |

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run the server with debug logging
PYTHONUNBUFFERED=1 netdia serve
```

### Database

Netdia uses SQLite with WAL mode for concurrent reads during scans. The database is created automatically at `NETDIA_DB_PATH` on first run. Schema migrations are handled in `database.py`.

To reset all data:

```bash
rm .netdia/netdia.db
```

## License

MIT
