# AGENTS.md — Hyping Repository Guide

This file follows the AGENTS.md convention: a plain Markdown, repo-root guide for AI coding agents. Treat it as the fast path for understanding this project before editing code.

## Project Snapshot

Hyping is a Python terminal network utility for macOS/local LAN workflows. Its purpose is pragmatic: quickly find nearby devices by hostname/note/IP/MAC, list devices on the current subnet, inspect mDNS/Bonjour metadata, save known devices, and run simple ICMP/TCP load tests.

Primary user experience is a Chinese terminal UI. Keep output clear, calm, and operational: users are often waiting on network discovery, permissions, Bettercap, DNS/mDNS, or Wi‑Fi SSID detection.

## Repository Map

```text
src/hyping/
  main.py                  # argparse CLI entrypoint; command wiring
  interactive.py           # interactive terminal UI and menu flows
  loadtest.py              # ICMP/TCP threaded load test + live renderer
  config.py                # JSON config defaults and ~/.hyping/config.json loader
  storage.py               # ~/.hyping/devices.json load/save/upsert helpers
  discovery/
    network.py             # default interface, Wi‑Fi SSID, subnet detection
    arp.py                 # Scapy ARP scanner; root often needed on macOS
    bettercap.py           # Bettercap REST API client and host parsing
    mdns.py                # dns-sd/Bonjour service discovery helpers
    resolver.py            # hostname/note/device resolution orchestration
  models/                  # small frozen dataclasses for devices/results/targets
  core/, packet/           # lower-level/experimental runtime and ICMP packet pieces

tests/                     # unittest/pytest-compatible test suite
README.md                  # human-facing usage docs
pyproject.toml             # package metadata, ruff config, Python requirement
requirements.txt           # runtime/tooling deps: scapy, ruff
```

Skip generated/local directories unless explicitly needed: `.venv-ft/`, `.ruff_cache/`, `.pytest_cache/`, `__pycache__/`, `src/hyping.egg-info/`, `.lh/`, `.DS_Store`.

## Setup and Common Commands

Use `PYTHONPATH=src` when running from a checkout.

```bash
# Optional existing local venv
source .venv-ft/bin/activate

# Install dependencies if the environment is missing them
python -m pip install -r requirements.txt

# Interactive UI
PYTHONPATH=src python -m hyping.main ui

# CLI examples
PYTHONPATH=src python -m hyping.main scan
PYTHONPATH=src python -m hyping.main locate --hostname SomeMac.local
PYTHONPATH=src python -m hyping.main load 192.168.1.10 --duration 10

# Validation
PYTHONPATH=src pytest -q
python -m ruff check src tests
python -m compileall -q src

# Focused validation while iterating
PYTHONPATH=src pytest tests/test_network.py -q
PYTHONPATH=src pytest tests/test_loadtest.py -q
```

If `pytest` is unavailable, most tests are `unittest` style and can also run with:

```bash
PYTHONPATH=src python -m unittest discover -s tests -q
```

## Coding Conventions

- Target Python is `>=3.10` per `pyproject.toml`; Python 3.14+ is recommended for development.
- Keep code dependency-light. Avoid adding large terminal UI frameworks unless the user explicitly asks; this project currently uses stdlib plus Scapy.
- Use type hints and small dataclasses where useful. Existing code favors explicit helpers over clever abstractions.
- Keep line length within Ruff’s configured `88` columns.
- Preserve `src/` package layout and import as `hyping...`; tests should use `PYTHONPATH=src`.
- Prefer pure parsing helpers that are easy to unit test, then thin OS/subprocess wrappers around them.
- Do not silently remove macOS-specific fallbacks. The app should degrade gracefully when commands are missing, redacted, permission-limited, or slow.

## Network and OS Behavior Guidelines

- macOS is the primary environment. Linux fallbacks exist for some networking calls, but do not assume feature parity.
- Active ARP scanning via Scapy often needs `sudo` on macOS. If not elevated, guide the user toward Bettercap or passive/system-cache flows instead of hard failing.
- Bettercap REST API is the default scanner path. Preserve API timeout/wait/poll settings and clear error messages.
- Wi‑Fi SSID detection should prefer robust macOS approaches. Recent macOS versions may redact older APIs; the preferred logic is based on `system_profiler SPAirPortDataType` and parsing `Current Network Information`.
- Do not repeatedly re-read SSID on every submenu return. Cache current network info in the UI where possible; provide an explicit refresh path when needed.
- For long operations, print a status line before blocking: scanning, reading SSID, Bettercap warmup, mDNS lookup, or load testing.

## Terminal UI Design Guide

The UI should feel modern without becoming noisy.

- Language: Chinese user-facing text by default. Keep technical terms like `SSID`, `TCP`, `mDNS`, `Bettercap` intact.
- Layout: show context first, then actions. A good screen order is title → status/context → selected/current device → numbered actions → prompt.
- Use concise labels with aligned values for parameter review screens.
- Prefer single-item parameter editing over forcing the user through every field.
- Every nested menu should have a clear “返回” path. If raw-key handling is available, `Esc` should mean “return one level up”.
- For blocking prompts, support Enter defaults. Display defaults explicitly.
- Use status text for waiting states, e.g. `正在读取 Wi‑Fi SSID...`, so the user knows the app is alive.
- Color palette: modern orange/cyan/teal accents, with muted gray separators. Colors must remain readable on both dark and light terminals.
- Honor `NO_COLOR` and non-TTY output. Never require ANSI color for comprehension.
- Avoid color-only meaning; include text labels such as `成功`, `失败`, `SSID`, `网段`.
- For live load tests, prefer compact real-time indicators: progress, throughput, latency, success/failure counts, and small sparkline/area trends.
- Use terminal width detection and clip long hostnames/notes instead of wrapping tables into unreadable output.

Example status style target:

```text
当前网络 Wi-Fi | SSID: SCBS-Student | 接口: en0 | 网段: 10.50.50.0/24
```

In color-capable terminals, distinguish the major tokens, not every character: label muted, network/interface cyan/teal, SSID orange, healthy numbers green, errors red.

## Interaction Logic to Preserve

Think like the user:

1. They start the UI to find or operate on a nearby device.
2. They need confidence that the app picked the right network/subnet.
3. They may search by partial hostname/note, then set a current device.
4. Once a current device exists, later flows should default to that device.
5. Load testing should summarize parameters before starting and allow precise edits.
6. Returning from submenus should be cheap and should not redo slow network probes unless requested.

When adding a menu, decide:

- What context does the user need before choosing?
- What is the safest default?
- How does the user back out?
- What feedback appears during waits?
- Which errors are recoverable and should return to the menu?

## Testing Expectations

- Add or update tests for parsing, config merging, storage updates, network-detection logic, Bettercap parsing, and load-test validation.
- Mock subprocess/network calls in tests. Do not require real Wi‑Fi, Bettercap, root, LAN devices, or internet.
- For UI changes, at minimum run import/compile checks and targeted tests around affected helpers.
- Before finishing a coding task, prefer running:

```bash
PYTHONPATH=src pytest -q
python -m ruff check src tests
```

If a full test cannot run because of missing local tools/deps, say exactly what failed and run the nearest focused check.

## Security and Safety

- Network scanning and load testing can affect other devices. Keep language clear that users should test only networks/devices they own or have permission to assess.
- Do not log or print saved Bettercap passwords except when explicitly editing config with user intent.
- Do not expand default scanning aggressiveness without a reason. For large Wi‑Fi networks, prefer batched/repeated ARP scans over huge bursts.
- Avoid adding telemetry or external network calls unrelated to the user’s requested network operation.

## Git and PR Hygiene

- Check `git status -sb` before editing and before summarizing. Do not overwrite unrelated user changes.
- Stage only files relevant to the task.
- Keep commits focused: one behavior/design change per commit when practical.
- Mention validation commands in the final response or PR body.
- Do not commit generated caches, `.DS_Store`, virtualenvs, or `__pycache__` files.

## Agent Communication Style

- Be concise but not cryptic. The user likes direct implementation with enough explanation to stay oriented.
- If the task is clear, act first and report what changed. Ask questions only when a wrong assumption would be risky.
- For Chinese prompts, reply in Chinese unless the user asks otherwise.
- Use small progress notes for multi-step work: inspect → edit → test → summarize.
- When a previous agent turn left uncommitted changes, explicitly distinguish existing changes from new edits.
- Final responses should include: changed files, key behavior, validation run, and any known caveats.
