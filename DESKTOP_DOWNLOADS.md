# Warden desktop downloads

For the quickest judge setup, download the installer for your platform from
the repository root:

- [Warden-macOS-arm64.dmg](Warden-macOS-arm64.dmg) - macOS on Apple Silicon
- [Warden.exe](Warden.exe) - Windows x64

## Install

On macOS, open the DMG and drag Warden to Applications. The package is not
Apple-notarized yet, so macOS may require Control-clicking Warden and choosing
Open on first launch.

On Windows, run `Warden.exe`. Windows SmartScreen may show a first-launch
warning because the executable is not code-signed yet.

The desktop app opens Warden in safe `mock` mode on a private loopback address.
It does not require Python, a terminal, browser URL, cloud credentials, or
billable cloud resources for the demo.

## Source fallback

If a platform security policy blocks the unsigned package, run Warden from
source:

```bash
git clone https://github.com/Somnora/Warden.git
cd Warden
python3 -m venv .venv
source .venv/bin/activate
pip install -e . && pytest
warden redteam
python demo.py
```

The macOS DMG was rebuilt from the current checkout on 2026-08-27. The Windows
binary is the existing x64 package and has not been runtime-tested on macOS;
the repository also contains a GitHub Actions workflow for producing a fresh
Windows build on Windows.
