#!/bin/bash
# Builds the CLEANING-ENABLED release app bundle build/iMop.app (iMop v1.1 "SafeClean").
#
# Debug builds (`swift run iMop`) are dry-run only. This script is the only place that compiles in
# IMOP_ALLOW_MUTATION (spec §0.5). Do not add that define to Package.swift, .vscode or any other script.
#
# Caveats (Milestone 8, not done yet):
#   - The bundle is NOT Developer ID signed, NOT built with Hardened Runtime and NOT notarized. The
#     binary only carries the linker's ad-hoc signature, so Gatekeeper treats the app as from an
#     unidentified developer (open it with right-click > Open the first time).
#   - SwiftPM resource bundles are also copied to the .app ROOT (see below). `codesign` refuses
#     bundles with unsealed content at the root ("unsealed contents present in the bundle root"), so
#     the notarized build must drop that copy once no code path uses `Bundle.module` any more.
#   - The binary is built for the host architecture only (spec §2 asks for arm64 + x86_64).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

APP_VERSION="1.1.0"
APP_BUILD="2"

# SAFETY-DECISION: the cleaning-enabled build gets its own scratch directory, so a binary compiled
# with IMOP_ALLOW_MUTATION never lands in the default .build folder used by `swift build` /
# `swift run` during development (where it could be mistaken for, or run instead of, a dry-run build).
SCRATCH_DIR="$PROJECT_DIR/.build/package-release"

echo "Building iMop $APP_VERSION ($APP_BUILD) with Swift Package Manager (release, IMOP_ALLOW_MUTATION)..."
SWIFT_EXEC="$SCRIPT_DIR/swiftc-wrapper.sh" swift build \
    --package-path "$PROJECT_DIR" \
    --scratch-path "$SCRATCH_DIR" \
    -c release \
    --product iMop \
    -Xswiftc -DIMOP_ALLOW_MUTATION

# Locate the binary: ask SwiftPM for its bin path first, then fall back to the known layouts.
BIN_PATH="$(SWIFT_EXEC="$SCRIPT_DIR/swiftc-wrapper.sh" swift build --package-path "$PROJECT_DIR" \
    --scratch-path "$SCRATCH_DIR" -c release --show-bin-path -Xswiftc -DIMOP_ALLOW_MUTATION 2>/dev/null || true)"
BUILD_BIN=""
for CANDIDATE in \
    "$BIN_PATH/iMop" \
    "$SCRATCH_DIR/release/iMop" \
    "$SCRATCH_DIR/out/Products/Release/iMop" \
    "$SCRATCH_DIR/arm64-apple-macosx/release/iMop" \
    "$SCRATCH_DIR/x86_64-apple-macosx/release/iMop"; do
    if [ -n "$CANDIDATE" ] && [ -f "$CANDIDATE" ]; then
        BUILD_BIN="$CANDIDATE"
        break
    fi
done
if [ -z "$BUILD_BIN" ]; then
    echo "ERROR: the release iMop binary was not found under $SCRATCH_DIR" >&2
    exit 1
fi
echo "Using binary $BUILD_BIN"

echo "Assembling iMop.app bundle..."
APP_DIR="$PROJECT_DIR/build/iMop.app"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"

rm -rf "$APP_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"

# Copy binary
cp "$BUILD_BIN" "$MACOS_DIR/iMop"
chmod +x "$MACOS_DIR/iMop"

# Copy icon and resources
for ICON in AppIcon.icns AppIcon.png AppIcon_UI.png; do
    if [ -f "$PROJECT_DIR/Resources/$ICON" ]; then
        cp "$PROJECT_DIR/Resources/$ICON" "$RESOURCES_DIR/$ICON"
    elif [ -f "$PROJECT_DIR/Sources/iMop/Resources/$ICON" ]; then
        cp "$PROJECT_DIR/Sources/iMop/Resources/$ICON" "$RESOURCES_DIR/$ICON"
    fi
done

# Copy every SwiftPM resource bundle built next to the binary (iMop_iMopCore.bundle holds Rules.json,
# iMop_iMop.bundle holds the app's images).
BUILD_DIR="$(dirname "$BUILD_BIN")"
FOUND_CORE_BUNDLE=0
shopt -s nullglob
for RESOURCE_BUNDLE in "$BUILD_DIR"/*.bundle; do
    BUNDLE_NAME="$(basename "$RESOURCE_BUNDLE")"
    echo "Copying resource bundle $BUNDLE_NAME"
    # Contents/Resources: where RuleCatalog.loadBundled looks first (Bundle.main.resourceURL). The
    # core never uses the SwiftPM `Bundle.module` accessor (it calls fatalError when its bundle is missing).
    rm -rf "$RESOURCES_DIR/$BUNDLE_NAME"
    cp -R "$RESOURCE_BUNDLE" "$RESOURCES_DIR/$BUNDLE_NAME"
    # App root: where the SwiftPM-generated `Bundle.module` accessor looks
    # (Bundle.main.bundleURL/<name>.bundle); the app target still uses it as an icon fallback.
    # NOTE: content at the .app root is unsealed for codesign; the notarized build (Milestone 8) must
    # drop this copy once no code path uses `Bundle.module` any more.
    rm -rf "$APP_DIR/$BUNDLE_NAME"
    cp -R "$RESOURCE_BUNDLE" "$APP_DIR/$BUNDLE_NAME"
    if [ "$BUNDLE_NAME" = "iMop_iMopCore.bundle" ]; then
        FOUND_CORE_BUNDLE=1
    fi
done
shopt -u nullglob
if [ "$FOUND_CORE_BUNDLE" -ne 1 ]; then
    echo "ERROR: iMop_iMopCore.bundle (Rules.json) was not found next to $BUILD_BIN" >&2
    exit 1
fi

# SAFETY-DECISION: without Rules.json the app loads an empty catalog (it never traps, it simply offers
# nothing), which would ship a cleaner that silently finds nothing. Fail the packaging step instead.
# SwiftPM produces either a flat bundle (Rules.json at its root) or a macOS-style bundle
# (Contents/Resources/Rules.json); RuleCatalog accepts both.
CORE_BUNDLE="$RESOURCES_DIR/iMop_iMopCore.bundle"
if [ ! -s "$CORE_BUNDLE/Rules.json" ] && [ ! -s "$CORE_BUNDLE/Contents/Resources/Rules.json" ]; then
    echo "ERROR: Rules.json is missing from $CORE_BUNDLE" >&2
    exit 1
fi

# Create Info.plist
cat <<EOF > "$CONTENTS_DIR/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>iMop</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIconName</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>com.imop.cleaner</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>iMop</string>
    <key>CFBundleDisplayName</key>
    <string>iMop</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>$APP_VERSION</string>
    <key>CFBundleVersion</key>
    <string>$APP_BUILD</string>
    <key>LSMinimumSystemVersion</key>
    <string>14.0</string>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSSupportsAutomaticGraphicsSwitching</key>
    <true/>
</dict>
</plist>
EOF

# Create PkgInfo
echo -n "APPL????" > "$CONTENTS_DIR/PkgInfo"

echo "iMop.app $APP_VERSION ($APP_BUILD) created at: $APP_DIR"
echo "This build CAN clean (IMOP_ALLOW_MUTATION). Until the manual QA checklist in SAFETY.md has passed,"
echo "run it only on a disposable macOS VM. It is not Developer ID signed or notarized (see SAFETY.md, Milestone 8)."
echo "Run it via: open \"$APP_DIR\""
