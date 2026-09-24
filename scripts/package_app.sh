#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "📦 Building iMop executable with Swift Package Manager..."
SWIFT_EXEC="$SCRIPT_DIR/swiftc-wrapper.sh" swift build --package-path "$PROJECT_DIR" -c release --product iMop

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
