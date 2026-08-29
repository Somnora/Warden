#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PYTHON="${ROOT_DIR}/.venv/bin/python"
DIST_DIR="${ROOT_DIR}/dist"
BUILD_DIR="${ROOT_DIR}/build/desktop-macos"
APP_PATH="${DIST_DIR}/Warden.app"
DMG_PATH="${DIST_DIR}/Warden-macOS-arm64.dmg"
APP_VERSION="$(cd "${ROOT_DIR}" && "${VENV_PYTHON}" -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"

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
  --icon "${ROOT_DIR}/assets/warden.icns" \
  --osx-bundle-identifier com.somnora.warden \
  --add-data "${ROOT_DIR}/warden/templates:warden/templates" \
  --add-data "${ROOT_DIR}/warden/static:warden/static" \
  --add-data "${ROOT_DIR}/warden/policy/policy.yaml:warden/policy" \
  --collect-all warden \
  --paths "${ROOT_DIR}" \
  --distpath "${DIST_DIR}" \
  --workpath "${BUILD_DIR}" \
  "${ROOT_DIR}/warden/desktop.py"

PLIST_PATH="${APP_PATH}/Contents/Info.plist"
if /usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "${PLIST_PATH}" >/dev/null 2>&1; then
  /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString ${APP_VERSION}" "${PLIST_PATH}"
else
  /usr/libexec/PlistBuddy -c "Add :CFBundleShortVersionString string ${APP_VERSION}" "${PLIST_PATH}"
fi
if /usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "${PLIST_PATH}" >/dev/null 2>&1; then
  /usr/libexec/PlistBuddy -c "Set :CFBundleVersion ${APP_VERSION}" "${PLIST_PATH}"
else
  /usr/libexec/PlistBuddy -c "Add :CFBundleVersion string ${APP_VERSION}" "${PLIST_PATH}"
fi
# Updating Info.plist invalidates PyInstaller's ad-hoc signature, so reseal the
# complete bundle. Production Developer ID signing can replace this identity.
codesign --force --deep --sign - "${APP_PATH}"

STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "${STAGE_DIR}"' EXIT
cp -R "${APP_PATH}" "${STAGE_DIR}/"
ln -s /Applications "${STAGE_DIR}/Applications"
hdiutil create -volname "Warden" -srcfolder "${STAGE_DIR}" -ov -format UDZO "${DMG_PATH}"
echo "Created ${DMG_PATH} (version ${APP_VERSION})"
