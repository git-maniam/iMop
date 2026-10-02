#!/bin/bash
# Builds the CLEANING-ENABLED release app bundle build/iMop.app (iMop v1.1 "SafeClean").
#
# Usage: scripts/package_app.sh [--host-only]
#   (default)    universal binary: arm64 and x86_64 are built separately, then merged with lipo (spec §2).
#   --host-only  a faster single-architecture build for the Mac you are on (local testing only).
#
# Debug builds (`swift run iMop`) are dry-run only. This script is the only place that compiles in
# IMOP_ALLOW_MUTATION (spec §0.5). Do not add that define to Package.swift, .vscode or any other script.
#
# Signing: this script does NOT sign. The binary only carries the linker's ad-hoc signature, which is
# enough for local runs (Gatekeeper treats the app as from an unidentified developer). For a
# distributable build run scripts/sign_and_notarize.sh afterwards (Developer ID, Hardened Runtime,
# notarization; see README › Distribution). The bundle assembled here is structurally signable:
# nothing but Contents/ at the .app root, and SwiftPM resource bundles only in Contents/Resources
# (no code path uses SwiftPM's `Bundle.module`, which would need them at the root; a test enforces this).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

APP_VERSION="1.1.0"
APP_BUILD="2"
MIN_MACOS="14.0"

HOST_ONLY=0
for ARG in "$@"; do
    case "$ARG" in
        --host-only) HOST_ONLY=1 ;;
        -h|--help)
            sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *)
            echo "ERROR: unknown option '$ARG' (usage: scripts/package_app.sh [--host-only])" >&2
            exit 2 ;;
    esac
done

if [ "$HOST_ONLY" -eq 1 ]; then
    ARCHS=("$(uname -m)")
else
    ARCHS=(arm64 x86_64)
fi

# SAFETY-DECISION: the cleaning-enabled build gets its own scratch directories (one per architecture),
# so a binary compiled with IMOP_ALLOW_MUTATION never lands in the default .build folder used by
# `swift build` / `swift run` during development (where it could be mistaken for, or run instead of,
# a dry-run build).
SCRATCH_BASE="$PROJECT_DIR/.build/package-release"

# Builds the release iMop product for one architecture; sets BUILD_BIN to the binary's path.
build_arch() {
    local ARCH="$1"
    local TRIPLE="$ARCH-apple-macosx$MIN_MACOS"
    local SCRATCH_DIR="$SCRATCH_BASE-$ARCH"
    echo "Building iMop $APP_VERSION ($APP_BUILD) for $TRIPLE (release, IMOP_ALLOW_MUTATION)..."
    SWIFT_EXEC="$SCRIPT_DIR/swiftc-wrapper.sh" swift build \
        --package-path "$PROJECT_DIR" \
        --scratch-path "$SCRATCH_DIR" \
        --triple "$TRIPLE" \
        -c release \
        --product iMop \
        -Xswiftc -DIMOP_ALLOW_MUTATION

    # Locate the binary: ask SwiftPM for its bin path first, then fall back to the known layouts.
    local BIN_PATH
    BIN_PATH="$(SWIFT_EXEC="$SCRIPT_DIR/swiftc-wrapper.sh" swift build --package-path "$PROJECT_DIR" \
        --scratch-path "$SCRATCH_DIR" --triple "$TRIPLE" -c release --show-bin-path \
        -Xswiftc -DIMOP_ALLOW_MUTATION 2>/dev/null || true)"
    BUILD_BIN=""
    local CANDIDATE
    for CANDIDATE in \
        "$BIN_PATH/iMop" \
        "$SCRATCH_DIR/$ARCH-apple-macosx/release/iMop" \
        "$SCRATCH_DIR/release/iMop" \
        "$SCRATCH_DIR/out/Products/Release/iMop"; do
        if [ -n "$CANDIDATE" ] && [ -f "$CANDIDATE" ]; then
            BUILD_BIN="$CANDIDATE"
            break
        fi
    done
    if [ -z "$BUILD_BIN" ]; then
        echo "ERROR: the release iMop binary for $ARCH was not found under $SCRATCH_DIR" >&2
        exit 1
    fi
    # The slice must really be the requested architecture (a build system that ignored --triple
    # would silently hand back a host binary).
    if [ "$(lipo -archs "$BUILD_BIN")" != "$ARCH" ]; then
        echo "ERROR: $BUILD_BIN is '$(lipo -archs "$BUILD_BIN")', expected '$ARCH'" >&2
        exit 1
    fi
    echo "Built $ARCH binary: $BUILD_BIN"
}

SLICES=()
FIRST_BUILD_BIN=""
for ARCH in "${ARCHS[@]}"; do
    build_arch "$ARCH"
    SLICES+=("$BUILD_BIN")
    if [ -z "$FIRST_BUILD_BIN" ]; then FIRST_BUILD_BIN="$BUILD_BIN"; fi
done

echo "Assembling iMop.app bundle..."
APP_DIR="$PROJECT_DIR/build/iMop.app"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"

rm -rf "$APP_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"
# Distributables and notary logs from an earlier sign_and_notarize.sh run describe the previous
# binary; remove them so build/ never holds a zip/dmg that does not match the freshly built app.
for STALE in "$PROJECT_DIR"/build/iMop-*.zip "$PROJECT_DIR"/build/iMop-*.dmg "$PROJECT_DIR"/build/notary-log-*.json; do
    if [ -e "$STALE" ]; then echo "Removing stale $(basename "$STALE")"; rm -f "$STALE"; fi
done

# Copy (single arch) or merge (universal) the binary.
if [ "${#SLICES[@]}" -eq 1 ]; then
    cp "${SLICES[0]}" "$MACOS_DIR/iMop"
else
    lipo -create "${SLICES[@]}" -output "$MACOS_DIR/iMop"
fi
chmod +x "$MACOS_DIR/iMop"

# Verify the architectures actually present in the bundled binary.
EXPECTED_ARCHS="$(printf '%s\n' "${ARCHS[@]}" | sort | tr '\n' ' ' | sed 's/ $//')"
ACTUAL_ARCHS="$(lipo -archs "$MACOS_DIR/iMop" | tr ' ' '\n' | sort | tr '\n' ' ' | sed 's/ $//')"
if [ "$ACTUAL_ARCHS" != "$EXPECTED_ARCHS" ]; then
    echo "ERROR: Contents/MacOS/iMop has architectures '$ACTUAL_ARCHS', expected '$EXPECTED_ARCHS'" >&2
    exit 1
fi
echo "Binary architectures: $(lipo -archs "$MACOS_DIR/iMop")"

# Copy icon and resources
for ICON in AppIcon.icns AppIcon.png AppIcon_UI.png; do
    if [ -f "$PROJECT_DIR/Resources/$ICON" ]; then
        cp "$PROJECT_DIR/Resources/$ICON" "$RESOURCES_DIR/$ICON"
    elif [ -f "$PROJECT_DIR/Sources/iMop/Resources/$ICON" ]; then
        cp "$PROJECT_DIR/Sources/iMop/Resources/$ICON" "$RESOURCES_DIR/$ICON"
    fi
done

# Copy every SwiftPM resource bundle built next to the binary (iMop_iMopCore.bundle holds Rules.json,
# iMop_iMop.bundle holds the app's images). Resource bundles hold no code, so the first architecture's
# copies serve the universal app.
#
# They go ONLY into Contents/Resources: RuleCatalog.loadBundled and BundledResourceLocator look there
# first (Bundle.main.resourceURL). Nothing is copied to the .app root: that is where SwiftPM's
# `Bundle.module` accessor would look, but no code path uses it (it calls fatalError when its bundle is
# missing), and content at the .app root is "unsealed contents present in the bundle root" to codesign.
BUILD_DIR="$(dirname "$FIRST_BUILD_BIN")"
FOUND_CORE_BUNDLE=0
shopt -s nullglob
for RESOURCE_BUNDLE in "$BUILD_DIR"/*.bundle; do
    BUNDLE_NAME="$(basename "$RESOURCE_BUNDLE")"
    echo "Copying resource bundle $BUNDLE_NAME into Contents/Resources"
    rm -rf "$RESOURCES_DIR/$BUNDLE_NAME"
    cp -R "$RESOURCE_BUNDLE" "$RESOURCES_DIR/$BUNDLE_NAME"
    if [ "$BUNDLE_NAME" = "iMop_iMopCore.bundle" ]; then
        FOUND_CORE_BUNDLE=1
    fi
done
shopt -u nullglob
if [ "$FOUND_CORE_BUNDLE" -ne 1 ]; then
    echo "ERROR: iMop_iMopCore.bundle (Rules.json) was not found next to $FIRST_BUILD_BIN" >&2
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

# Structural check for codesign: the .app root must contain nothing but Contents/ (in particular no
# *.bundle left over from older versions of this script).
ROOT_EXTRAS="$(cd "$APP_DIR" && ls -A | grep -vx 'Contents' || true)"
if [ -n "$ROOT_EXTRAS" ]; then
    echo "ERROR: unexpected items at the .app root (codesign would reject them): $ROOT_EXTRAS" >&2
    exit 1
fi

echo "iMop.app $APP_VERSION ($APP_BUILD) created at: $APP_DIR ($(lipo -archs "$MACOS_DIR/iMop"))"
echo "This build CAN clean (IMOP_ALLOW_MUTATION). Until the manual QA checklist in SAFETY.md has passed,"
echo "run it only on a disposable macOS VM. It is NOT Developer ID signed or notarized yet:"
echo "run ./scripts/sign_and_notarize.sh for a distributable build (see README › Distribution)."
echo "Run it via: open \"$APP_DIR\""
