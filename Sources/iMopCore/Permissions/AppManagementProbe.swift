import Foundation

// App Management probe (spec §8). macOS offers no reliable read-only way to find out whether iMop
// may modify other apps' bundles, so the probe always answers `.unknown`; the permission is only
// requested when the user selects a rule that moves an app bundle to the Trash, and a refusal is
// reported by the Executor when it happens.

/// Answers whether iMop has the App Management permission. Injectable for tests.
public protocol AppManagementProbing: Sendable {
    func appManagementState() -> PermissionState
}

public struct AppManagementProbe: AppManagementProbing {
    /// System Settings › Privacy & Security › App Management.
    public static let settingsDeepLink = "x-apple.systempreferences:com.apple.preference.security?Privacy_AppBundles"

    /// Shown when moving an app bundle to the Trash is refused.
    public static let permissionNeededMessage =
        "App Management permission is needed to move this app to the Trash. Allow iMop in System Settings › Privacy & Security › App Management, then try again."

    /// Rules whose items are whole app bundles (they need App Management).
    public static let appBundleRuleIDs: Set<String> = ["xcode.extraInstalls", "installers.macOS"]

    public init() {}

    /// SAFETY-DECISION: no probe ever tries to change an app bundle to find out, so the answer is
    /// always `.unknown`; callers must not treat it as granted.
    public func appManagementState() -> PermissionState { .unknown }

    /// `true` when `path` names an app bundle (last component ends in `.app`, case-insensitive).
    public static func isAppBundlePath(_ path: String) -> Bool {
        var trimmed = path
        while trimmed.count > 1 && trimmed.hasSuffix("/") { trimmed.removeLast() }
        guard let last = trimmed.split(separator: "/").last else { return false }
        return last.count > 4 && last.lowercased().hasSuffix(".app")
    }

    /// `true` for the errors macOS reports when App Management is not granted (EPERM / EACCES,
    /// directly or as the underlying POSIX error of a Cocoa no-permission error).
    public static func isPermissionError(_ error: any Error) -> Bool {
        if let posix = error as? POSIXError { return isPermissionErrno(posix.code.rawValue) }
        let nsError = error as NSError
        if nsError.domain == NSPOSIXErrorDomain { return isPermissionErrno(Int32(nsError.code)) }
        if let underlying = nsError.userInfo[NSUnderlyingErrorKey] as? NSError, underlying.domain == NSPOSIXErrorDomain {
            return isPermissionErrno(Int32(underlying.code))
        }
        if nsError.domain == NSCocoaErrorDomain {
            return nsError.code == NSFileWriteNoPermissionError || nsError.code == NSFileReadNoPermissionError
        }
        return false
    }

    public static func isPermissionErrno(_ code: Int32) -> Bool { code == EPERM || code == EACCES }

    /// The message the Executor reports for a refused Trash move of `path`: `permissionNeededMessage`
    /// when `path` is an app bundle and `error` is a permission error, otherwise `nil` (use the
    /// normal error mapping).
    public static func failureMessage(movingToTrash path: String, error: any Error) -> String? {
        guard isAppBundlePath(path), isPermissionError(error) else { return nil }
        return permissionNeededMessage
    }

    /// errno form of `failureMessage(movingToTrash:error:)`.
    public static func failureMessage(movingToTrash path: String, errno code: Int32) -> String? {
        guard isAppBundlePath(path), isPermissionErrno(code) else { return nil }
        return permissionNeededMessage
    }
}

/// Both permission probes, injectable as one value (tests pass fakes).
public struct PermissionProbes: Sendable {
    public let fullDiskAccess: any FullDiskAccessProbing
    public let appManagement: any AppManagementProbing

    public init(fullDiskAccess: any FullDiskAccessProbing, appManagement: any AppManagementProbing) {
        self.fullDiskAccess = fullDiskAccess
        self.appManagement = appManagement
    }

    /// The real probes, reading through `environment` (the fixture environment in tests).
    public static func live(environment: SafeCleanEnvironment) -> PermissionProbes {
        PermissionProbes(fullDiskAccess: FullDiskAccessProbe(environment: environment), appManagement: AppManagementProbe())
    }
}
