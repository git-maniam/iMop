#!/bin/bash

REAL_SWIFT="/Library/Developer/CommandLineTools/usr/bin/swiftc"
REAL_SYM='_$s18PackageDescription0A0C4name19defaultLocalization9platforms9pkgConfig9providers8products12dependencies7targets21swiftLanguageVersions01cN8Standard03cxxnP0ACSS_AA0N3TagVSgSayAA17SupportedPlatformVGSgSSSgSayAA06SystemA8ProviderOGSgSayAA7ProductCGSayAC10DependencyCGSayAA6TargetCGSayAA05SwiftN4ModeOGSgAA09CLanguageP0OSgAA011CXXLanguageP0OSgtcfC'
ALIAS_SYM='_$s18PackageDescription0A0C4name19defaultLocalization9platforms9pkgConfig9providers8products12dependencies7targets21swiftLanguageVersions01cN8Standard03cxxnP0ACSS_AA0N3TagVSgSayAA17SupportedPlatformVGSgSSSgSayAA06SystemA8ProviderOGSgSayAA7ProductCGSayAC10DependencyCGSayAA6TargetCGSayAA12SwiftVersionOGSgAA09CLanguageP0OSgAA011CXXLanguageP0OSgtcfC'

# Check if compiling a package manifest (contains -lPackageDescription)
HAS_PKG_DESC=false
for arg in "$@"; do
    if [[ "$arg" == "-lPackageDescription" ]]; then
        HAS_PKG_DESC=true
        break
    fi
done

if [ "$HAS_PKG_DESC" = true ]; then
    exec "$REAL_SWIFT" "$@" -Xlinker -alias -Xlinker "$REAL_SYM" -Xlinker "$ALIAS_SYM"
else
    exec "$REAL_SWIFT" "$@"
fi
