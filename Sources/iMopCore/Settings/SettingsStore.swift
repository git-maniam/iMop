import Foundation

// Persistence of the user's `ScanSettings` (spec §9.9, Milestone 7).
//
// The settings are stored as one JSON-encoded `ScanSettings` value in the app's user defaults. Only
// iMop's own preferences are written here; nothing in this file touches any other file.

/// Raw key/value storage behind a `SettingsStore` (user defaults in the app, memory in tests).
@_spi(FixtureTesting)
public protocol SettingsBacking: AnyObject, Sendable {
    func data(forKey key: String) -> Data?
    func set(_ data: Data?, forKey key: String)
}

/// `UserDefaults`-backed storage.
final class UserDefaultsSettingsBacking: SettingsBacking, @unchecked Sendable {
    // `UserDefaults` is documented as thread-safe.
    private let defaults: UserDefaults

    init(defaults: UserDefaults) {
        self.defaults = defaults
    }

    func data(forKey key: String) -> Data? { defaults.data(forKey: key) }

    func set(_ data: Data?, forKey key: String) {
        if let data {
            defaults.set(data, forKey: key)
        } else {
            defaults.removeObject(forKey: key)
        }
    }
}

/// In-memory storage for tests (never touches the real preferences).
@_spi(FixtureTesting)
public final class InMemorySettingsBacking: SettingsBacking, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: Data] = [:]

    public init(values: [String: Data] = [:]) {
        self.values = values
    }

    public func data(forKey key: String) -> Data? {
        lock.lock(); defer { lock.unlock() }
        return values[key]
    }

    public func set(_ data: Data?, forKey key: String) {
        lock.lock(); defer { lock.unlock() }
        values[key] = data
    }
}

/// Loads and saves the user's `ScanSettings`.
public final class SettingsStore: @unchecked Sendable {
    /// The app's bundle identifier, used as the user-defaults suite when iMop runs unbundled
    /// (`swift run iMop`).
    public static let suiteName = "com.imop.cleaner"
    /// Key of the JSON-encoded `ScanSettings`.
    public static let settingsKey = "safeclean.scanSettings.v1"

    /// The app's persistent store.
    public static let standard = SettingsStore(backing: UserDefaultsSettingsBacking(defaults: defaultUserDefaults()))

    private let backing: any SettingsBacking
    private let lock = NSLock()
    private var _lastLoadFellBackToDefaults = false

    init(backing: any SettingsBacking) {
        self.backing = backing
    }

    /// Test-only: a store over specific user defaults.
    @_spi(FixtureTesting)
    public convenience init(defaults: UserDefaults) {
        self.init(backing: UserDefaultsSettingsBacking(defaults: defaults))
    }

    /// Test-only: a store over arbitrary storage (e.g. `InMemorySettingsBacking`).
    @_spi(FixtureTesting)
    public convenience init(testBacking: any SettingsBacking) {
        self.init(backing: testBacking)
    }

    /// Test-only: an in-memory store, optionally pre-filled with raw (possibly corrupted) data.
    @_spi(FixtureTesting)
    public static func inMemory(rawData: Data? = nil) -> SettingsStore {
        let backing = InMemorySettingsBacking()
        if let rawData { backing.set(rawData, forKey: settingsKey) }
        return SettingsStore(backing: backing)
    }

    /// Test-only: the raw stored bytes.
    @_spi(FixtureTesting)
    public var rawData: Data? {
        get { backing.data(forKey: Self.settingsKey) }
        set { backing.set(newValue, forKey: Self.settingsKey) }
    }

    /// Key under which unreadable stored settings are kept (never overwritten automatically).
    public static let backupKey = "safeclean.scanSettings.v1.unreadableBackup"

    private var _lastLoadUnreadableFields: [String] = []

    /// `true` when the last `load()` found stored data it could not read completely (some fields, or
    /// all of it) and used the defaults for what it could not read.
    public var lastLoadFellBackToDefaults: Bool {
        lock.lock(); defer { lock.unlock() }
        return _lastLoadFellBackToDefaults
    }

    /// Plain-language names of the settings the last `load()` could not read (empty when the data was
    /// unreadable as a whole or everything was read).
    public var lastLoadUnreadableFields: [String] {
        lock.lock(); defer { lock.unlock() }
        return _lastLoadUnreadableFields
    }

    /// Test-only: the backed-up unreadable data, if any.
    @_spi(FixtureTesting)
    public var backupData: Data? { backing.data(forKey: Self.backupKey) }

    /// The stored settings, or `ScanSettings.default` when nothing is stored.
    ///
    /// SAFETY-DECISION (review M7): every field is read on its own, so one unreadable field can never
    /// erase the others (in particular the user's exclusions). A field that cannot be read uses its
    /// safe default ("Always quarantine" ON, remembered drives `nil` = never recorded, which pauses
    /// orphan detection); in a list of paths only the unreadable entries are dropped. Whenever
    /// anything could not be read, `lastLoadFellBackToDefaults` is set (AppState then pauses cleaning
    /// until the user has checked Settings) and the original bytes are kept under `backupKey`, which
    /// later saves never overwrite.
    public func load() -> ScanSettings {
        let data = backing.data(forKey: Self.settingsKey)
        var fellBack = false
        var unreadable: [String] = []
        var settings = ScanSettings.default
        if let data {
            if let lenient = try? JSONDecoder().decode(LenientScanSettings.self, from: data) {
                settings = lenient.settings
                unreadable = lenient.unreadable
                fellBack = !unreadable.isEmpty
            } else {
                fellBack = true
                settings = ScanSettings.default
            }
            if fellBack, backing.data(forKey: Self.backupKey) == nil {
                backing.set(data, forKey: Self.backupKey)
            }
        }
        lock.lock()
        _lastLoadFellBackToDefaults = fellBack
        _lastLoadUnreadableFields = unreadable
        lock.unlock()
        return settings
    }

    /// Persists `settings`. Returns `false` when they could not be encoded (nothing is written then).
    @discardableResult
    public func save(_ settings: ScanSettings) -> Bool {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard let data = try? encoder.encode(settings) else { return false }
        backing.set(data, forKey: Self.settingsKey)
        return true
    }

    /// The defaults domain of the app.
    ///
    /// Inside the bundled app (`com.imop.cleaner`) that is `UserDefaults.standard` (a suite named after
    /// the app's own identifier is not allowed); when run unbundled it is the `com.imop.cleaner` suite.
    static func defaultUserDefaults() -> UserDefaults {
        if Bundle.main.bundleIdentifier == suiteName { return .standard }
        return UserDefaults(suiteName: suiteName) ?? .standard
    }
}

// MARK: - Field-by-field decoding

/// Decodes `ScanSettings` one field at a time (see `SettingsStore.load()`).
private struct LenientScanSettings: Decodable {
    var settings = ScanSettings.default
    var unreadable: [String] = []

    private struct Key: CodingKey {
        var stringValue: String
        var intValue: Int? { nil }
        init(_ string: String) { stringValue = string }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { nil }
    }

    /// One element of a list of strings; `nil` when it is not a string.
    private struct LossyString: Decodable {
        let value: String?
        init(from decoder: any Decoder) throws {
            value = try? decoder.singleValueContainer().decode(String.self)
        }
    }

    init(from decoder: any Decoder) throws {
        // A top level that is not an object is unreadable as a whole (the caller uses the defaults).
        let c = try decoder.container(keyedBy: Key.self)

        func value<T: Decodable>(_ type: T.Type, _ key: String, _ label: String) -> T? {
            let k = Key(key)
            guard c.contains(k) else { return nil }
            if let decoded = try? c.decode(T.self, forKey: k) { return decoded }
            unreadable.append(label)
            return nil
        }

        /// A list of strings: unreadable entries are dropped (and reported); `nil` when absent.
        func strings(_ key: String, _ label: String) -> (values: [String], complete: Bool)? {
            let k = Key(key)
            guard c.contains(k) else { return nil }
            guard let list = try? c.decode([LossyString].self, forKey: k) else {
                unreadable.append(label)
                return ([], false)
            }
            let values = list.compactMap(\.value)
            if values.count != list.count { unreadable.append(label) }
            return (values, values.count == list.count)
        }

        if let roots = strings("projectRoots", "project folders") { settings.projectRoots = roots.values }
        if let exclusions = strings("userExclusions", "exclusions") { settings.userExclusions = exclusions.values }
        if let keep = value(Int.self, "archivesToKeep", "archives to keep") { settings.archivesToKeep = keep }
        if let ages = value([String: Int].self, "ageThresholdOverrides", "age thresholds") { settings.ageThresholdOverrides = ages }
        // SAFETY-DECISION: an unreadable value keeps the safe default (ON).
        if let always = value(Bool.self, "alwaysQuarantine", "Always quarantine") { settings.alwaysQuarantine = always }
        if let retention = value([String: Int].self, "quarantineRetentionOverrideHours", "retention") {
            settings.quarantineRetentionOverrideHours = retention
        }
        // SAFETY-DECISION: "Trust Homebrew tools" is ON only for a readable `true`; absence → OFF,
        // anything unreadable → OFF (and reported, which pauses cleaning until Settings are checked).
        if let trust = value(Bool.self, "trustHomebrewAdminWritableDirectories", "Trust Homebrew tools") {
            settings.trustHomebrewAdminWritableDirectories = trust
        }
        // SAFETY-DECISION (review M6): explicit null, absence, or any unreadable entry → `nil` ("never
        // recorded"), which pauses orphan detection until a scan records the connected drives again.
        let volumesKey = Key("lastSeenVolumes")
        if c.contains(volumesKey), (try? c.decodeNil(forKey: volumesKey)) != true,
           let volumes = strings("lastSeenVolumes", "remembered drives") {
            settings.lastSeenVolumes = volumes.complete ? volumes.values : nil
        }
    }
}
