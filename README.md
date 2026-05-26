<div align="center">

<img src="whatsrunning-logo.png" width="96" alt="WhatsRunning logo">

# WhatsRunning

**Task Manager, in plain English.**

A free Windows process inspector that explains what every process on your PC actually is, who made it, and whether it should be running — in language anyone can read.

[Download for Windows](https://github.com/HandrollDev/whatsrunning/releases/latest) · [Website](https://whatsrunning.app) · [Support on Ko-fi](https://ko-fi.com/handroll)

</div>

---

## Why this exists

Open Task Manager and you'll see two hundred processes with cryptic names like `svchost.exe`, `dwm.exe`, `dllhost.exe`. Most people have no idea what any of them do, which are safe to close, or whether the new one that just appeared is part of Windows or part of a problem.

WhatsRunning answers those questions in plain English. It pulls together a curated database of common Windows processes, Windows' own digital-signature verification, and a set of malware-pattern heuristics, then explains each running process in a sentence or two: *what it does, who published it, why it's running, and whether you can safely close it.*

It is **not** an antivirus, and it does not pretend to be one. Think of it as a translator between Task Manager and a normal person.

## Features

- **Plain-English description for every process** — curated for the most common ~280 Windows binaries; smart synthesis (publisher + install path + signature) for the rest.
- **Risk badges that explain themselves** — every "Suspicious" or "Low Risk" flag tells you the specific reason it fired.
- **Catalog-aware signature verification** — uses the same Windows API your OS uses, so it correctly accepts Microsoft Store apps and catalog-signed system binaries.
- **One-shot scanning** — nothing runs in the background. Open the app, click Scan, see the results, close the app.
- **Five quick actions per process** — open file location, copy path, search online, look up on VirusTotal (privacy-preserving hash search, no upload), or end the process.
- **No telemetry, no analytics, no ads.** The only network calls happen when *you* click a specific button.

## Screenshots

<!-- Replace with real screenshots once captured -->

_Coming soon — see [whatsrunning.app](https://whatsrunning.app) for a preview of the UI._

## Install

The released binary is a single 50 MB `.exe` — no installer, no setup.

1. Grab `WhatsRunning.exe` from the [latest release](https://github.com/HandrollDev/whatsrunning/releases/latest).
2. Verify the SHA-256 hash (also on the Releases page) matches what you downloaded.
3. Double-click. SmartScreen may warn you because the binary isn't code-signed yet — click *"More info"* → *"Run anyway"*.

## If your antivirus flags it

Some antivirus products — most often **Norton**, **Avast**, and **AVG** — may flag `WhatsRunning.exe` as `IDP.Generic`, `FileRepMalware`, `Win64:UnwantedX-gen`, or a similar generic name. These are **reputation heuristics**, not actual malware detections. They fire because:

- The binary isn't code-signed (certificates cost hundreds a year — not viable yet for a free tool).
- It's new and hasn't accumulated download reputation in the vendor's cloud.
- It's PyInstaller-packed, which superficially resembles some malware packing patterns.

**What to do:**

1. Verify the SHA-256 matches the value on the [Releases page](https://github.com/HandrollDev/whatsrunning/releases/latest) — that confirms you have the same bytes every other user has.
2. Cross-check on [VirusTotal](https://www.virustotal.com/). If only one or two vendors flag it as something generic, it's the same false-positive class indie software hits constantly.
3. Add the file to your antivirus's exceptions list if you want to run it.

Reputation builds cumulatively on the SHA, which is why the website `.exe` is intentionally stable — code updates ship via the in-app updater so trust accumulates on a single binary rather than resetting with every release.

If running unsigned software isn't acceptable to you, building from source (below) is supported.

## Privacy

WhatsRunning was written with a strict no-background-phone-home rule:

- **Process scans run 100% locally.** No data leaves your machine during a scan.
- The only times the app talks to the network are when *you* click a specific button:
  - **Search online** opens Google in your browser.
  - **Check on VirusTotal** opens VirusTotal pointed at the file's SHA-256 hash. The file itself is never uploaded.
  - **Support development** opens the Ko-fi page.
  - **Check for updates** makes a single request to GitHub's public API to compare your version against the latest release.
- No telemetry, no analytics, no anonymous usage stats, no cookies — none of it.

## How it differs from what you already have

- **vs. Windows Defender:** Defender catches *known malware* from its signature database. It doesn't comment on the dozens of legitimate-looking processes you don't recognise. WhatsRunning explains all of them.
- **vs. Process Explorer / Process Hacker:** Those are excellent and powerful, but written by power users for power users — forty columns of acronyms, no descriptions, no risk indicators. WhatsRunning is for the people Process Explorer terrifies.
- **vs. Googling each process name yourself:** Faster, doesn't require 200 browser tabs, answers come from a single curated source instead of a hundred "what is svchost.exe?" SEO articles.

## Building from source

You need Python 3.10+ and PySide6.

```powershell
git clone https://github.com/HandrollDev/whatsrunning.git
cd whatsrunning
pip install -r requirements.txt

# Run from source:
python whatsrunning.py

# Build the single-file .exe:
python build_icon.py
python -m PyInstaller --noconfirm whatsrunning.spec
# -> dist/WhatsRunning.exe
```

## Project structure

| File | Purpose |
|---|---|
| `whatsrunning.py` | PySide6 GUI — main window, details panel, action handlers |
| `scanner.py` | Process enumeration, signature verification, heuristics |
| `process_database.py` | Curated database of known processes + publisher purpose hints |
| `build_icon.py` | Regenerates `whatsrunning.ico` from scratch using Pillow |
| `whatsrunning.spec` | PyInstaller build configuration |
| `site/index.html` | Self-contained landing page |

## Contributing

The most useful contribution is **adding entries to `process_database.py`** for processes that currently show up as "Unknown" on your machine. Two patterns:

- **Specific binary** → add an entry to `PROCESS_DB` with a user-centric description (what it does, why it's running, whether it's safe to close).
- **Whole publisher's stuff is unrecognised** → add one line to `PUBLISHER_PURPOSE` that describes the company's product category. Covers all their `.exe` files at once.

PRs welcome.

## Related projects

- [**WhatsRunning for Android**](https://github.com/mirfatif/WhatsRunning) by [@mirfatif](https://github.com/mirfatif) — a separate project sharing the same name. It's a process monitor for Android devices (requires root or ADB). Different platform, different scope. If you're on Android, check it out.

## License

[MIT](LICENSE). Use it, fork it, build on it — just keep the copyright notice.

## Support

If WhatsRunning has saved you 10 minutes of Googling, [buy me a coffee on Ko-fi](https://ko-fi.com/handroll). It's appreciated.
