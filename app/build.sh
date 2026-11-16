#!/bin/bash
# Build Gatehouse.app (and dist/Gatehouse.zip) from this checkout.
#
#   app/build.sh              native architecture
#   app/build.sh --universal  Apple Silicon and Intel (needs Xcode)
#
# Signs ad hoc unless GATEHOUSE_SIGN_ID names a Developer ID identity.
set -euo pipefail
APP_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$APP_DIR/.." && pwd)"
OUT="$REPO/dist"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO/pyproject.toml")"

ARCHS=()
[[ "${1:-}" == --universal ]] && ARCHS=(--arch arm64 --arch x86_64)
cd "$APP_DIR"
swift build -c release ${ARCHS[@]+"${ARCHS[@]}"}
BIN="$(swift build -c release ${ARCHS[@]+"${ARCHS[@]}"} --show-bin-path)/Gatehouse"

APP="$OUT/Gatehouse.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/payload"
cp "$BIN" "$APP/Contents/MacOS/Gatehouse"
cp "$APP_DIR/Resources/AppIcon.icns" "$APP/Contents/Resources/" 2>/dev/null || true

# The service the app installs: only tracked files, so nothing local (venvs, state) slips in.
git -C "$REPO" ls-files -z --cached --others --exclude-standard src deploy pyproject.toml README.md LICENSE \
  | (cd "$REPO" && xargs -0 tar -cf -) | tar -xf - -C "$APP/Contents/Resources/payload"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Gatehouse</string>
  <key>CFBundleDisplayName</key><string>Gatehouse</string>
  <key>CFBundleIdentifier</key><string>io.github.gatehouse.app</string>
  <key>CFBundleExecutable</key><string>Gatehouse</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHumanReadableCopyright</key><string>Apache License 2.0</string>
  <key>NSAppTransportSecurity</key><dict><key>NSAllowsLocalNetworking</key><true/></dict>
</dict>
</plist>
PLIST

codesign --force --deep --options runtime --sign "${GATEHOUSE_SIGN_ID:--}" "$APP"
rm -f "$OUT/Gatehouse.zip"
ditto -c -k --keepParent "$APP" "$OUT/Gatehouse.zip"
echo "Built $APP ($VERSION) and $OUT/Gatehouse.zip"
