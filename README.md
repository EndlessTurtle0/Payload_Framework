# Payload Frameworks

A concise, modular CLI toolkit that generates static payload templates for defensive security training and academic study. All outputs are non-executable templates intended for offline lab use only; this project does not perform network activity or interact with live targets.

## Table of Contents

- [Quick summary](#quick-summary)
- [Installation](#installation)
- [Usage](#usage)
- [Modules](#modules)
- [Project structure](#project-structure)
- [Output formats](#output-formats)
- [Ethical use](#ethical-use)
- [Contributing](#contributing)
- [Examples](#examples)

## Quick summary

- Context-aware payload templates for XSS, SQLi, and command-injection
- Encoding utilities: URL, Base64, hex, and mixed chains
- OS- and DB-aware variations for realistic simulations
- Export options: console, JSON, plain TXT for scanner integration

## Overview

### What this project is

`Payload Frameworks` is a modular command-line toolkit that produces structured, static payload templates for learning and defensive security testing. It is explicitly designed for offline lab use and educational research — it does not send network traffic or target live systems.

### Focus areas

- Cross-Site Scripting (XSS)
- SQL Injection (SQLi)
- Command Injection
- Encoding & obfuscation techniques

### Purpose

The project was created to:

- Demonstrate how common injection payloads are constructed
- Illustrate how weak input validation leads to vulnerabilities
- Show simple techniques WAFs may miss or mis-handle
- Provide a safe lab environment for defensive research and teaching

### Framework architecture

The system follows a layered, modular design:

User CLI input
      ↓
Module selection / configuration
      ↓
Payload generator (templates)
      ↓
Encoding & obfuscation pipeline
      ↓
Output (console / JSON / TXT)

### Available modules (summary)

- XSS module
      - Reflected / stored / DOM-style templates
      - Tag switching, case manipulation, and encoding variants

- SQLi module
      - DB-aware templates for MySQL, PostgreSQL, MSSQL
      - Union-based, error-based, and comment/whitespace bypass patterns
      - NOTE: no database interaction is performed

- Command-injection module
      - OS-aware separators and payload patterns
      - Linux examples: `;`, `&&`, `|`
      - Windows examples: `&`, `||`, `|`

- Encoding & obfuscation engine
      - URL, Base64, hex and mixed-encoding chains
      - Whitespace manipulation and inline-comment techniques

> Safety note: modules only generate static templates for analysis and training. They do not execute payloads or interact with external systems.

## Installation

Clone and install dependencies:

```powershell
git clone https://github.com/EndlessTurtle0/Payload_Framework.git
cd Payload_Framework
pip install -r requirements.txt
```

## Usage

Run a module from the CLI. Examples:

```powershell
python main.py --module xss
python main.py --module sqli --db mysql
python main.py --module cmdi --encode base64
python main.py --module xss --output payloads.json
```

## Modules

- `xss` — Reflected, stored and DOM-style XSS templates, with tag/case variations
- `sqli` — MySQL / PostgreSQL / MSSQL templates (union-based, error-based, comment bypasses)
- `cmdi` — Command-injection templates with OS-aware separators and bypass patterns
- `encoder` — Encoding/obfuscation helpers (URL, Base64, hex, mixed chains)

> Note: Modules generate static payload templates only; there is no live exploitation.

## Project structure

- `main.py` — CLI entrypoint
- `modules/` — Payload generators (`xss.py`, `sqli.py`, `cmdi.py`)
- `utils/` — Helpers (encoding, exporting)
- `samples/` — Example payload lists

## Output formats

- **Console** — Immediate CLI output
- **JSON** — Structured payload export
- **TXT** — Plain lists for scanner import (Burp/ZAP)

## Ethical use

Intended usage:

- Academic research and coursework
- Authorized penetration testing and red-team work
- Lab-based security training and defensive WAF testing

Do not use this project to attack systems without explicit authorization. The authors are not responsible for misuse.

## Contributing

To add a payload category:

1. Create a new module file under `modules/`
2. Implement a generator class with the project's generator interface
3. Register the module in `main.py` and connect it to the encoder/exporter

## Examples

- XSS: `"><script>alert(1)</script>`
- SQLi: `' UNION SELECT NULL,NULL-- -`
- CMDi: `; whoami`

---

If you'd like, I can also update the repository description on GitHub to a concise sentence (recommended) and set topics — I just need a GitHub PAT or `GH_TOKEN` in your environment to do that.
---

If you'd like I can also: run a quick lint/format, update `requirements.txt`, or convert this README into a shorter quickstart. Tell me which next step you prefer.
