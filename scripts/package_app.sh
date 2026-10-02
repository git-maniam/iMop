#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "📦 Building iMop executable with Swift Package Manager..."
# SafeClean (spec §0.5): only this release packaging step compiles in IMOP_ALLOW_MUTATION, the flag
# that lets the Executor / Quarantine actually move or remove files. Debug builds (`swift run iMop`)
# never pass it and stay dry-run. Never add this define to Package.swift.
SWIFT_EXEC="$SCRIPT_DIR/swiftc-wrapper.sh" swift build --package-path "$PROJECT_DIR" -c release --product iMop -Xswiftc -DIMOP_ALLOW_MUTATION

BUILD_BIN="$PROJECT_DIR/.build/release/iMop"
if [ ! -f "$BUILD_BIN" ]; then
    BUILD_BIN="$PROJECT_DIR/.build/out/release/iMop"
fi
if [ ! -f "$BUILD_BIN" ]; then
    BUILD_BIN="$PROJECT_DIR/.build/arm64-apple-macosx/release/iMop"
fi

# Fallback: locate the binary
if [ ! -f "$BUILD_BIN" ]; then
    BUILD_BIN=$(find "$PROJECT_DIR/.build" -type f -name "iMop" -perm +111 | head -n 1)
fi

echo "🚀 Assembling iMop.app bundle..."
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
if [ -f "$PROJECT_DIR/Resources/AppIcon.icns" ]; then
    cp "$PROJECT_DIR/Resources/AppIcon.icns" "$RESOURCES_DIR/AppIcon.icns"
fi
if [ -f "$PROJECT_DIR/Resources/AppIcon.png" ]; then
    cp "$PROJECT_DIR/Resources/AppIcon.png" "$RESOURCES_DIR/AppIcon.png"
fi
if [ -f "$PROJECT_DIR/Resources/AppIcon_UI.png" ]; then
    cp "$PROJECT_DIR/Resources/AppIcon_UI.png" "$RESOURCES_DIR/AppIcon_UI.png"
fi

# Copy every SwiftPM resource bundle built next to the binary (iMop_iMopCore.bundle holds Rules.json,
# iMop_iMop.bundle holds the app's images). A missing bundle would make the generated `Bundle.module`
# accessor call fatalError at runtime, so a missing iMopCore bundle fails the packaging step instead.
BUILD_DIR="$(dirname "$BUILD_BIN")"
FOUND_CORE_BUNDLE=0
shopt -s nullglob
for RESOURCE_BUNDLE in "$BUILD_DIR"/*.bundle; do
    BUNDLE_NAME="$(basename "$RESOURCE_BUNDLE")"
    echo "📚 Copying resource bundle $BUNDLE_NAME"
    # Contents/Resources: where SafeClean's RuleCatalog looks first (Bundle.main.resourceURL).
    rm -rf "$RESOURCES_DIR/$BUNDLE_NAME"
    cp -R "$RESOURCE_BUNDLE" "$RESOURCES_DIR/$BUNDLE_NAME"
    # App root: where the SwiftPM-generated `Bundle.module` accessor looks
    # (Bundle.main.bundleURL/<name>.bundle). NOTE: content at the .app root is unsealed for
    # codesign; the notarized build (Milestone 8) must drop this copy once no code path uses
    # `Bundle.module` any more.
    rm -rf "$APP_DIR/$BUNDLE_NAME"
    cp -R "$RESOURCE_BUNDLE" "$APP_DIR/$BUNDLE_NAME"
    if [ "$BUNDLE_NAME" = "iMop_iMopCore.bundle" ]; then
        FOUND_CORE_BUNDLE=1
    fi
done
shopt -u nullglob
if [ "$FOUND_CORE_BUNDLE" -ne 1 ]; then
    echo "❌ iMop_iMopCore.bundle (Rules.json) was not found next to $BUILD_BIN" >&2
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
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
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

echo "✨ iMop.app successfully created at: $APP_DIR"
echo "👉 You can run it via: open \"$APP_DIR\""
