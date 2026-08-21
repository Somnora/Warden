$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root ".venv\Scripts\python.exe"
$Dist = Join-Path $Root "dist"
$Build = Join-Path $Root "build\desktop-windows"

if (-not (Test-Path $Python)) {
    throw "Create the project virtual environment first: py -3.12 -m venv .venv"
}

& $Python -m pip install -e "$Root[desktop]" pyinstaller
if ((Test-Path $Build) -or (Test-Path (Join-Path $Dist "Warden.exe"))) {
    throw "Existing desktop build output detected. Move or delete build\\desktop-windows and dist\\Warden.exe before rebuilding."
}

& $Python -m PyInstaller `
    --noconfirm `
    --onefile `
    --windowed `
    --name Warden `
    --add-data "$Root\warden\templates;warden\templates" `
    --add-data "$Root\warden\policy\policy.yaml;warden\policy" `
    --collect-all warden `
    --paths $Root `
    --distpath $Dist `
    --workpath $Build `
    "$Root\warden\desktop.py"

Write-Host "Created $(Join-Path $Dist 'Warden.exe')"
