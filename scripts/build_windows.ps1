$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root ".venv\Scripts\python.exe"
$Dist = Join-Path $Root "dist"
$Build = Join-Path $Root "build\desktop-windows"
$PyProject = Get-Content (Join-Path $Root "pyproject.toml") -Raw
$VersionMatch = [regex]::Match(
    $PyProject,
    '(?m)^version\s*=\s*"([0-9]+)\.([0-9]+)\.([0-9]+)"'
)
if (-not $VersionMatch.Success) {
    throw "Could not read the project version from pyproject.toml"
}
$Version = (
    $VersionMatch.Groups[1].Value + "." +
    $VersionMatch.Groups[2].Value + "." +
    $VersionMatch.Groups[3].Value
)
$VersionTuple = (
    $VersionMatch.Groups[1].Value + ", " +
    $VersionMatch.Groups[2].Value + ", " +
    $VersionMatch.Groups[3].Value + ", 0"
)
$VersionFile = [System.IO.Path]::GetTempFileName()

if (-not (Test-Path $Python)) {
    throw "Create the project virtual environment first: py -3.12 -m venv .venv"
}

& $Python -m pip install -e "$Root[desktop]" pyinstaller
if ((Test-Path $Build) -or (Test-Path (Join-Path $Dist "Warden.exe"))) {
    throw "Existing desktop build output detected. Move or delete build\\desktop-windows and dist\\Warden.exe before rebuilding."
}

try {
    @"
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=($VersionTuple),
    prodvers=($VersionTuple),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040904B0',
        [StringStruct('CompanyName', 'Somnora'),
         StringStruct('FileDescription', 'Warden governed agent control plane'),
         StringStruct('FileVersion', '$Version'),
         StringStruct('InternalName', 'Warden'),
         StringStruct('OriginalFilename', 'Warden.exe'),
         StringStruct('ProductName', 'Warden'),
         StringStruct('ProductVersion', '$Version')]
      )
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"@ | Set-Content -Path $VersionFile -Encoding UTF8

    & $Python -m PyInstaller `
        --noconfirm `
        --onefile `
        --windowed `
        --name Warden `
        --icon "$Root\assets\warden.ico" `
        --version-file $VersionFile `
        --add-data "$Root\warden\templates;warden\templates" `
        --add-data "$Root\warden\static;warden\static" `
        --add-data "$Root\warden\policy\policy.yaml;warden\policy" `
        --collect-all warden `
        --paths $Root `
        --distpath $Dist `
        --workpath $Build `
        "$Root\warden\desktop.py"
}
finally {
    Remove-Item $VersionFile -ErrorAction SilentlyContinue
}

Write-Host "Created $(Join-Path $Dist 'Warden.exe') (version $Version)"
