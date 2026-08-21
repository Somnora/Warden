#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PYTHON="${ROOT_DIR}/.venv/bin/python"
DIST_DIR="${ROOT_DIR}/dist"
BUILD_DIR="${ROOT_DIR}/build/desktop-macos"
APP_PATH="${DIST_DIR}/Warden.app"
DMG_PATH="${DIST_DIR}/Warden-macOS-arm64.dmg"

if [[ ! -x "${VENV_PYTHON}" ]]; then
  echo "Create the project virtual environment first: python3 -m venv .venv" >&2
  exit 1
fi

"${VENV_PYTHON}" -m pip install -e "${ROOT_DIR}[desktop]" pyinstaller
if [[ -e "${BUILD_DIR}" || -e "${APP_PATH}" || -e "${DMG_PATH}" ]]; then
  echo "Existing desktop build output detected. Move or delete build/desktop-macos and dist/Warden* before rebuilding." >&2
  exit 1
fi

"${VENV_PYTHON}" -m PyInstaller \
  --noconfirm \
  --windowed \
  --name Warden \
  --osx-bundle-identifier com.somnora.warden \
  --add-data "${ROOT_DIR}/warden/templates:warden/templates" \
  --add-data "${ROOT_DIR}/warden/static:warden/static" \
  --add-data "${ROOT_DIR}/warden/policy/policy.yaml:warden/policy" \
  --collect-all warden \
  --paths "${ROOT_DIR}" \
  --distpath "${DIST_DIR}" \
  --workpath "${BUILD_DIR}" \
  "${ROOT_DIR}/warden/desktop.py"

STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "${STAGE_DIR}"' EXIT
cp -R "${APP_PATH}" "${STAGE_DIR}/"
ln -s /Applications "${STAGE_DIR}/Applications"
hdiutil create -volname "Warden" -srcfolder "${STAGE_DIR}" -ov -format UDZO "${DMG_PATH}"
echo "Created ${DMG_PATH}"
