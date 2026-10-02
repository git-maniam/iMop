#!/bin/bash
# Signs build/iMop.app with a Developer ID Application certificate and the Hardened Runtime, notarizes
# and staples it, and produces the distributables build/iMop-<version>.zip and (optionally)
# build/iMop-<version>.dmg. Spec §2: arm64 + x86_64, Developer ID, Hardened Runtime, notarized, NOT
# sandboxed, no network entitlement, no get-task-allow.
#
# Usage: scripts/sign_and_notarize.sh [--identity "Developer ID Application: Name (TEAMID)"]
#                                     [--profile imop-notary] [--no-dmg] [--adhoc]
#   --identity  signing identity (name or SHA-1 hash). Default: the only "Developer ID Application"
#               identity in your keychain (an error if there are none or several).
#   --profile   notarytool keychain profile (default: imop-notary), created once with
#               xcrun notarytool store-credentials (see README › Distribution).
#   --no-dmg    only produce the notarized .zip, no .dmg.
#   --adhoc     local structural check WITHOUT a certificate: ad-hoc signature + Hardened Runtime,
#               strict verification and entitlement checks; no notarization. NOT distributable.
#
# Run ./scripts/package_app.sh first. This script never uses sudo, never passes --deep when signing,
# uses no entitlements file (the app needs none), and never prints credentials (notarytool reads them
# from the keychain profile).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_DIR/build"
APP="$BUILD_DIR/iMop.app"

IDENTITY=""
PROFILE="imop-notary"
MAKE_DMG=1
ADHOC=0

usage() { sed -n '7,15p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "ERROR: $*" >&2; exit 1; }
step() { echo; echo "==> $*"; }
# need_value OPTION VALUE...: the option needs a value that is not itself an option (so that
# "--profile --no-dmg" is a usage error rather than silently swallowing --no-dmg).
need_value() {
    [ $# -ge 2 ] || die "$1 needs a value"
    case "$2" in -*|"") die "$1 needs a value (got '$2')" ;; esac
}

while [ $# -gt 0 ]; do
    case "$1" in
        --identity) need_value "$@"; IDENTITY="$2"; shift 2 ;;
        --identity=*) IDENTITY="${1#*=}"; need_value --identity "$IDENTITY"; shift ;;
        --profile) need_value "$@"; PROFILE="$2"; shift 2 ;;
        --profile=*) PROFILE="${1#*=}"; need_value --profile "$PROFILE"; shift ;;
        --no-dmg) MAKE_DMG=0; shift ;;
        --adhoc) ADHOC=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option '$1'" ;;
    esac
done
[ -n "$PROFILE" ] || die "--profile must not be empty"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/imop-sign.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

# ---------------------------------------------------------------------------------------------------
step "Preflight"
[ -d "$APP" ] || die "$APP not found. Build it first: ./scripts/package_app.sh"
PLIST="$APP/Contents/Info.plist"
[ -f "$PLIST" ] || die "$PLIST is missing; rebuild with ./scripts/package_app.sh"
plist_value() { /usr/libexec/PlistBuddy -c "Print :$1" "$PLIST" 2>/dev/null || true; }
VERSION="$(plist_value CFBundleShortVersionString)"
BUILD_NUMBER="$(plist_value CFBundleVersion)"
EXECUTABLE="$(plist_value CFBundleExecutable)"
BUNDLE_ID="$(plist_value CFBundleIdentifier)"
[ -n "$VERSION" ] || die "CFBundleShortVersionString is missing from Info.plist"
[ -n "$EXECUTABLE" ] || die "CFBundleExecutable is missing from Info.plist"
BIN="$APP/Contents/MacOS/$EXECUTABLE"
[ -f "$BIN" ] || die "the app binary $BIN is missing"

ARCHS="$(lipo -archs "$BIN" 2>/dev/null || true)"
case " $ARCHS " in *" arm64 "*) ;; *) die "binary is '$ARCHS', not universal (needs arm64 and x86_64). Run ./scripts/package_app.sh without --host-only" ;; esac
case " $ARCHS " in *" x86_64 "*) ;; *) die "binary is '$ARCHS', not universal (needs arm64 and x86_64). Run ./scripts/package_app.sh without --host-only" ;; esac

# codesign rejects anything but Contents/ at the bundle root ("unsealed contents present in the bundle root").
ROOT_EXTRAS="$(cd "$APP" && ls -A | grep -vx 'Contents' || true)"
[ -z "$ROOT_EXTRAS" ] || die "unexpected items at the .app root: $(echo "$ROOT_EXTRAS" | tr '\n' ' ')- rebuild with ./scripts/package_app.sh"
# Same check as package_app.sh: Rules.json must be inside iMop_iMopCore.bundle, where RuleCatalog
# looks (macOS-style or flat bundle layout). A stray Rules.json elsewhere does not count.
CORE_BUNDLE="$APP/Contents/Resources/iMop_iMopCore.bundle"
if [ ! -s "$CORE_BUNDLE/Contents/Resources/Rules.json" ] && [ ! -s "$CORE_BUNDLE/Rules.json" ]; then
    die "Rules.json is missing from $CORE_BUNDLE; rebuild with ./scripts/package_app.sh"
fi
echo "App:      $APP"
echo "Bundle:   $BUNDLE_ID  version $VERSION ($BUILD_NUMBER)"
echo "Binary:   $ARCHS"

# ---------------------------------------------------------------------------------------------------
if [ "$ADHOC" -eq 1 ]; then
    SIGN_IDENTITY="-"
    echo "Mode:     --adhoc (ad-hoc signature, no certificate, no notarization)"
else
    step "Signing identity"
    IDENTITIES="$(security find-identity -v -p codesigning 2>/dev/null || true)"
    # One line per certificate: the same certificate can be listed once per keychain on the search
    # list, so deduplicate by SHA-1 hash (field 2).
    DEVID_LINES="$(echo "$IDENTITIES" | grep '"Developer ID Application:' | awk '!seen[$2]++' || true)"
    HOW_TO_GET='Create one (needs a paid Apple Developer Program membership): Xcode › Settings › Accounts ›
select your team › Manage Certificates… › + › Developer ID Application. Or create it at
https://developer.apple.com/account/resources/certificates and double-click the downloaded .cer.
Then check: security find-identity -v -p codesigning'
    if [ -n "$IDENTITY" ]; then
        # The given identity must be a valid Developer ID Application identity in the keychain, matched
        # exactly: a 40-hex-digit SHA-1 hash (any case) against the hash column, otherwise the full
        # quoted certificate name. No substring matching, so "--identity Ravi" selects nothing.
        if echo "$IDENTITY" | grep -Eq '^[0-9A-Fa-f]{40}$'; then
            WANT_HASH="$(echo "$IDENTITY" | tr '[:lower:]' '[:upper:]')"
            MATCH="$(echo "$DEVID_LINES" | awk -v h="$WANT_HASH" 'toupper($2)==h' || true)"
        else
            MATCH="$(echo "$DEVID_LINES" | awk -F'"' -v n="$IDENTITY" '$2==n' || true)"
        fi
        [ -n "$MATCH" ] || die "no valid \"Developer ID Application\" identity matching '$IDENTITY' in your keychain.
Pass the exact certificate name as listed by 'security find-identity -v -p codesigning', or its 40-digit SHA-1 hash.
Notarization requires a Developer ID Application certificate (not \"Apple Development\" or \"Mac App Distribution\").
$HOW_TO_GET"
        [ "$(echo "$MATCH" | grep -c .)" -eq 1 ] || die "'$IDENTITY' matches several certificates with the same name (e.g. an old
and a renewed one); they differ only by SHA-1 hash, so pass the hash of the one to use with --identity:
$MATCH"
    else
        COUNT="$(echo "$DEVID_LINES" | grep -c . || true)"
        if [ "$COUNT" -eq 0 ]; then
            die "no \"Developer ID Application\" signing identity found in your keychain.
$HOW_TO_GET
To check the bundle structure without a certificate, run: ./scripts/sign_and_notarize.sh --adhoc --no-dmg"
        elif [ "$COUNT" -gt 1 ]; then
            die "several \"Developer ID Application\" identities found; choose one with --identity <SHA-1 hash>
(the hash tells certificates with the same name apart, e.g. after a renewal):
$DEVID_LINES"
        fi
        MATCH="$DEVID_LINES"
    fi
    # Use the SHA-1 hash (unambiguous even with duplicate names); show the name.
    SIGN_IDENTITY="$(echo "$MATCH" | awk '{print $2}')"
    IDENTITY_NAME="$(echo "$MATCH" | sed -E 's/^[^"]*"(.*)"[^"]*$/\1/')"
    echo "Identity: $IDENTITY_NAME"

    step "Notary profile '$PROFILE'"
    # Validates the stored credentials before anything is signed (output discarded; nothing secret is printed).
    if ! xcrun notarytool history --keychain-profile "$PROFILE" >/dev/null 2>"$TMP_DIR/profile.err"; then
        echo "notarytool could not use the keychain profile '$PROFILE':" >&2
        sed 's/^/    /' "$TMP_DIR/profile.err" >&2
        die "store your notarization credentials once (use an app-specific password from https://account.apple.com › Sign-In and Security › App-Specific Passwords):
    xcrun notarytool store-credentials $PROFILE --apple-id <your Apple ID e-mail> --team-id <TEAMID>
(notarytool then prompts for the app-specific password and stores it in your login keychain;
 you can also pass --password <app-specific password>, but that leaves it in your shell history)."
    fi
    echo "Profile OK."
fi

# ---------------------------------------------------------------------------------------------------
# Re-signing changes the app, so any distributables from an earlier run no longer match it. Remove them
# (these exact paths only) so a failed run never leaves an older or un-notarized zip/dmg at the path
# that would be uploaded. New ones are built in $TMP_DIR and moved here only after they pass.
ZIP="$BUILD_DIR/iMop-$VERSION.zip"
DMG="$BUILD_DIR/iMop-$VERSION.dmg"
for STALE in "$ZIP" "$DMG" "$BUILD_DIR"/notary-log-*.json; do
    if [ -e "$STALE" ]; then echo "Removing stale $(basename "$STALE")"; rm -f "$STALE"; fi
done

step "Signing $APP"
# Finder info / resource forks make codesign fail ("detritus not allowed"); strip them from the build output.
xattr -cr "$APP" 2>/dev/null || true
# No --deep: the bundle has one executable (Contents/MacOS) and the resource bundles in
# Contents/Resources hold no code, so they are sealed as resources of the app. No entitlements file:
# the app is not sandboxed and needs no network or debugging entitlement.
if [ "$ADHOC" -eq 1 ]; then
    codesign --force --options runtime --sign - "$APP"
else
    codesign --force --timestamp --options runtime --sign "$SIGN_IDENTITY" "$APP"
fi

step "Verifying the signature"
codesign --verify --strict --deep --verbose=2 "$APP"

# If codesign cannot report the entitlements, fail: an empty result only means "no entitlements" when
# codesign itself succeeded.
codesign -d --entitlements - --xml "$APP" > "$TMP_DIR/entitlements.plist" 2>"$TMP_DIR/entitlements.err" \
    || die "could not read the entitlements of $APP: $(cat "$TMP_DIR/entitlements.err")"
for FORBIDDEN in get-task-allow com.apple.security.network com.apple.security.app-sandbox \
                 com.apple.security.cs.disable-library-validation com.apple.security.cs.allow-dyld-environment-variables; do
    if grep -q "$FORBIDDEN" "$TMP_DIR/entitlements.plist"; then
        die "the signature carries the entitlement '$FORBIDDEN' (the release build must have none)"
    fi
done
if grep -q "<key>" "$TMP_DIR/entitlements.plist"; then
    echo "Entitlements:" >&2; cat "$TMP_DIR/entitlements.plist" >&2
    die "the signature carries entitlements; iMop needs none"
fi
echo "Entitlements: none (no get-task-allow, no network, not sandboxed)"

codesign -dvvv "$APP" > "$TMP_DIR/sig.txt" 2>&1 || true
grep -E '^CodeDirectory .*flags=0x[0-9a-f]+\([^)]*runtime[^)]*\)' "$TMP_DIR/sig.txt" >/dev/null \
    || { cat "$TMP_DIR/sig.txt" >&2; die "the Hardened Runtime flag (runtime) is not set"; }
grep -E '^(Identifier|Format|CodeDirectory|Signature|Authority|TeamIdentifier|Timestamp)' "$TMP_DIR/sig.txt" || true
grep -q "^Identifier=$BUNDLE_ID\$" "$TMP_DIR/sig.txt" || die "the signature identifier is not $BUNDLE_ID"

if [ "$ADHOC" -eq 1 ]; then
    echo
    echo "Ad-hoc signed and verified: Hardened Runtime on, no entitlements, bundle structure accepted by codesign."
    echo "THIS BUILD IS NOT DISTRIBUTABLE: it has no Developer ID signature and is not notarized, so"
    echo "Gatekeeper on other Macs will block it. Notarization, stapling, spctl and the DMG were skipped."
    echo "For a release run: ./scripts/package_app.sh && ./scripts/sign_and_notarize.sh"
    exit 0
fi

grep -q '^Authority=Developer ID Application:' "$TMP_DIR/sig.txt" || die "the signature is not a Developer ID Application signature"
grep -q '^Timestamp=' "$TMP_DIR/sig.txt" || die "the signature has no secure timestamp (notarization requires --timestamp)"

# ---------------------------------------------------------------------------------------------------
# notarize FILE: submits FILE, waits, and fails (with the log saved under build/) unless Accepted.
notarize() {
    local FILE="$1"
    local OUT="$TMP_DIR/submit-$(basename "$FILE").json"
    step "Notarizing $(basename "$FILE") (this usually takes a few minutes)"
    local RC=0
    xcrun notarytool submit "$FILE" --keychain-profile "$PROFILE" --wait --output-format json > "$OUT" 2>"$OUT.err" || RC=$?
    local ID STATUS
    ID="$(plutil -extract id raw -o - "$OUT" 2>/dev/null || true)"
    STATUS="$(plutil -extract status raw -o - "$OUT" 2>/dev/null || true)"
    echo "Submission id: ${ID:-<none>}  status: ${STATUS:-<unknown>}"
    if [ "$STATUS" != "Accepted" ]; then
        [ -s "$OUT.err" ] && sed 's/^/    /' "$OUT.err" >&2
        [ -s "$OUT" ] && sed 's/^/    /' "$OUT" >&2
        if [ -n "$ID" ]; then
            local LOG="$BUILD_DIR/notary-log-$ID.json"
            xcrun notarytool log "$ID" --keychain-profile "$PROFILE" "$LOG" >/dev/null 2>&1 \
                && echo "Notary log saved to $LOG (see its \"issues\" list)." >&2 \
                || echo "Could not fetch the notary log; try: xcrun notarytool log $ID --keychain-profile $PROFILE" >&2
        fi
        die "notarization of $(basename "$FILE") was not accepted (status '${STATUS:-unknown}', notarytool exit $RC)"
    fi
}

UPLOAD_ZIP="$TMP_DIR/iMop-$VERSION-upload.zip"
step "Creating the upload archive"
ditto -c -k --keepParent "$APP" "$UPLOAD_ZIP"
notarize "$UPLOAD_ZIP"

step "Stapling the ticket to the app"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"
SPCTL_OUT="$(spctl --assess --type execute -vvv "$APP" 2>&1 || true)"
echo "$SPCTL_OUT"
echo "$SPCTL_OUT" | grep -q "source=Notarized Developer ID" || die "Gatekeeper does not accept the app as 'Notarized Developer ID'"

step "Creating the distributable zip (stapled app)"
ditto -c -k --keepParent "$APP" "$TMP_DIR/dist.zip"
mv -f "$TMP_DIR/dist.zip" "$ZIP"
echo "Created $ZIP"

if [ "$MAKE_DMG" -eq 1 ]; then
    # Built under $TMP_DIR (with the final file name, which notarytool shows) and moved to build/ only
    # after signing, notarization, stapling and Gatekeeper assessment all pass.
    mkdir -p "$TMP_DIR/dmg"
    TMP_DMG="$TMP_DIR/dmg/$(basename "$DMG")"
    step "Creating $(basename "$DMG")"
    hdiutil create -volname iMop -srcfolder "$APP" -ov -format UDZO "$TMP_DMG"
    codesign --force --timestamp --sign "$SIGN_IDENTITY" "$TMP_DMG"
    codesign --verify --strict --verbose=2 "$TMP_DMG"
    notarize "$TMP_DMG"
    xcrun stapler staple "$TMP_DMG"
    xcrun stapler validate "$TMP_DMG"
    DMG_SPCTL="$(spctl --assess --type open --context context:primary-signature -vvv "$TMP_DMG" 2>&1 || true)"
    echo "$DMG_SPCTL"
    echo "$DMG_SPCTL" | grep -q "source=Notarized Developer ID" || die "Gatekeeper does not accept the DMG as 'Notarized Developer ID'"
    mv -f "$TMP_DMG" "$DMG"
    echo "Created $DMG"
fi

echo
echo "Done. Signed, notarized and stapled: $APP"
if [ "$MAKE_DMG" -eq 1 ]; then
    echo "Distributables: $ZIP and $DMG"
else
    echo "Distributable: $ZIP"
fi
echo "Before publishing: test on a clean Mac / VM (download via a browser, no Gatekeeper warning),"
echo "grant Full Disk Access again (macOS ties it to the signature), and run the manual QA checklist in SAFETY.md."
