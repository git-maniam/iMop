import Foundation
@_spi(FixtureTesting) import iMopCore

/// Realistic, static outputs of the read-only vendor listings used by the Milestone 4 command
/// inspectors (Discovery/SimctlClient.swift, DockerClient.swift, OllamaClient.swift), captured from
/// real tools and anonymised. Tests feed them to `FakeCommandRunner`; nothing here runs a command.
///
/// Placeholders: `{HOME}` in simctl JSON is replaced by `devicesJSON(home:)` etc. with the fixture
/// home (simctl escapes "/" as "\/" in its JSON; both spellings parse).
enum CommandFixtures {
    // MARK: - Keys for FakeCommandRunner (arguments joined by " ")

    static let xcrunPath = "/usr/bin/xcrun"
    static let dockerPath = "/usr/local/bin/docker"
    static let ollamaPath = "/opt/homebrew/bin/ollama"

    static var simctlListDevicesKey: [String] { SimctlClient.listDevicesArguments }
    static var simctlListUnavailableKey: [String] { SimctlClient.listUnavailableDevicesArguments }
    static var simctlRuntimeListKey: [String] { SimctlClient.listRuntimesArguments }

    // MARK: - UDIDs used below

    /// Shutdown, available, old (tests age its folder past 90 days).
    static let staleUDID = "A47CD2C9-0C68-4140-A0B1-925934040AD2"
    /// Shutdown, available, recently used.
    static let freshUDID = "39AF2A04-4F3F-46BE-B256-55C820834550"
    /// Booted — never offered.
    static let bootedUDID = "7DC9A8FF-5F97-430D-8DAA-D37FA584A428"
    /// Unavailable (runtime no longer installed).
    static let unavailableUDID1 = "D03F9286-CB36-433E-ADE0-A67768864F77"
    static let unavailableUDID2 = "5B78FA61-BF98-42C9-84CE-0D5A391AC87F"
    /// Deletable runtime image.
    static let deletableRuntimeID = "08CA48EA-CFAF-41A4-B829-1AD1F1866837"
    /// Non-deletable (bundled) runtime image.
    static let bundledRuntimeID = "6E1A3B2C-91D4-4F5E-8A7B-0C9D8E7F6A5B"

    // MARK: - xcrun simctl list devices -j

    static let devicesJSONTemplate = #"""
    {
      "devices" : {
        "com.apple.CoreSimulator.SimRuntime.iOS-27-0" : [
          {
            "dataPath" : "{HOME}\/Library\/Developer\/CoreSimulator\/Devices\/A47CD2C9-0C68-4140-A0B1-925934040AD2\/data",
            "dataPathSize" : 18337792,
            "logPath" : "{HOME}\/Library\/Logs\/CoreSimulator\/A47CD2C9-0C68-4140-A0B1-925934040AD2",
            "udid" : "A47CD2C9-0C68-4140-A0B1-925934040AD2",
            "isAvailable" : true,
            "deviceTypeIdentifier" : "com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro",
            "state" : "Shutdown",
            "name" : "iPhone 18 Pro"
          },
          {
            "dataPath" : "{HOME}\/Library\/Developer\/CoreSimulator\/Devices\/39AF2A04-4F3F-46BE-B256-55C820834550\/data",
            "dataPathSize" : 18337792,
            "logPath" : "{HOME}\/Library\/Logs\/CoreSimulator\/39AF2A04-4F3F-46BE-B256-55C820834550",
            "udid" : "39AF2A04-4F3F-46BE-B256-55C820834550",
            "isAvailable" : true,
            "deviceTypeIdentifier" : "com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro-Max",
            "state" : "Shutdown",
            "name" : "iPhone 18 Pro Max"
          },
          {
            "dataPath" : "{HOME}\/Library\/Developer\/CoreSimulator\/Devices\/7DC9A8FF-5F97-430D-8DAA-D37FA584A428\/data",
            "dataPathSize" : 18337792,
            "logPath" : "{HOME}\/Library\/Logs\/CoreSimulator\/7DC9A8FF-5F97-430D-8DAA-D37FA584A428",
            "udid" : "7DC9A8FF-5F97-430D-8DAA-D37FA584A428",
            "isAvailable" : true,
            "deviceTypeIdentifier" : "com.apple.CoreSimulator.SimDeviceType.iPhone-17e",
            "state" : "Booted",
            "name" : "iPhone 17e"
          }
        ],
        "com.apple.CoreSimulator.SimRuntime.watchOS-12-0" : [

        ]
      }
    }
    """#

    /// `xcrun simctl list devices -j` with `{HOME}` replaced by `home`.
    static func devicesJSON(home: String) -> String {
        devicesJSONTemplate.replacingOccurrences(of: "{HOME}", with: home.replacingOccurrences(of: "/", with: "\\/"))
    }

    /// Every device shut down (simulatorIdle passes).
    static func devicesJSONAllShutdown(home: String) -> String {
        devicesJSON(home: home).replacingOccurrences(of: "\"state\" : \"Booted\"", with: "\"state\" : \"Shutdown\"")
    }

    /// A device whose data lives outside the default device set — never offered.
    static let devicesJSONForeignDataPath = #"""
    {
      "devices" : {
        "com.apple.CoreSimulator.SimRuntime.iOS-27-0" : [
          {
            "dataPath" : "\/Volumes\/External\/Simulators\/A47CD2C9-0C68-4140-A0B1-925934040AD2\/data",
            "udid" : "A47CD2C9-0C68-4140-A0B1-925934040AD2",
            "isAvailable" : true,
            "state" : "Shutdown",
            "name" : "iPhone 18 Pro"
          }
        ]
      }
    }
    """#

    // MARK: - xcrun simctl list devices unavailable -j

    static let unavailableDevicesJSONTemplate = #"""
    {
      "devices" : {
        "com.apple.CoreSimulator.SimRuntime.iOS-17-5" : [
          {
            "dataPath" : "{HOME}\/Library\/Developer\/CoreSimulator\/Devices\/D03F9286-CB36-433E-ADE0-A67768864F77\/data",
            "dataPathSize" : 1207959552,
            "logPath" : "{HOME}\/Library\/Logs\/CoreSimulator\/D03F9286-CB36-433E-ADE0-A67768864F77",
            "udid" : "D03F9286-CB36-433E-ADE0-A67768864F77",
            "isAvailable" : false,
            "availabilityError" : "runtime profile not found using \"System\" match policy",
            "deviceTypeIdentifier" : "com.apple.CoreSimulator.SimDeviceType.iPhone-15",
            "state" : "Shutdown",
            "name" : "iPhone 15"
          },
          {
            "dataPath" : "{HOME}\/Library\/Developer\/CoreSimulator\/Devices\/5B78FA61-BF98-42C9-84CE-0D5A391AC87F\/data",
            "dataPathSize" : 804257792,
            "logPath" : "{HOME}\/Library\/Logs\/CoreSimulator\/5B78FA61-BF98-42C9-84CE-0D5A391AC87F",
            "udid" : "5B78FA61-BF98-42C9-84CE-0D5A391AC87F",
            "isAvailable" : false,
            "availabilityError" : "runtime profile not found using \"System\" match policy",
            "deviceTypeIdentifier" : "com.apple.CoreSimulator.SimDeviceType.iPad-Air-11-inch-M2",
            "state" : "Shutdown",
            "name" : "iPad Air 11-inch (M2)"
          }
        ]
      }
    }
    """#

    static func unavailableDevicesJSON(home: String) -> String {
        unavailableDevicesJSONTemplate.replacingOccurrences(of: "{HOME}", with: home.replacingOccurrences(of: "/", with: "\\/"))
    }

    /// Real output when nothing is unavailable.
    static let unavailableDevicesJSONEmpty = #"""
    {
      "devices" : {
        "com.apple.CoreSimulator.SimRuntime.iOS-27-0" : [

        ]
      }
    }
    """#

    // MARK: - xcrun simctl runtime list -j

    static let runtimeListJSON = #"""
    {
      "08CA48EA-CFAF-41A4-B829-1AD1F1866837" : {
        "build" : "24A434",
        "deletable" : true,
        "identifier" : "08CA48EA-CFAF-41A4-B829-1AD1F1866837",
        "kind" : "Patchable Cryptex Disk Image",
        "mountPath" : "\/private\/var\/run\/com.apple.security.cryptexd\/mnt\/com.apple.iPhoneOS.SimulatorRuntime-v24.1.434.0.GLArAT",
        "path" : "\/System\/Library\/AssetsV2\/com_apple_MobileAsset_iOSSimulatorRuntime\/3e800c38767f9f2c5fc86acdad7adf44565e051a.asset\/AssetData",
        "platformIdentifier" : "com.apple.platform.iphonesimulator",
        "runtimeBundlePath" : "\/private\/var\/run\/com.apple.security.cryptexd\/mnt\/com.apple.iPhoneOS.SimulatorRuntime-v24.1.434.0.GLArAT\/Library\/Developer\/CoreSimulator\/Profiles\/Runtimes\/iOS 27.0.simruntime",
        "runtimeIdentifier" : "com.apple.CoreSimulator.SimRuntime.iOS-27-0",
        "signatureState" : "Unknown",
        "sizeBytes" : 8067000161,
        "state" : "Ready",
        "supportedArchitectures" : [
          "arm64"
        ],
        "version" : "27.0"
      },
      "6E1A3B2C-91D4-4F5E-8A7B-0C9D8E7F6A5B" : {
        "build" : "23R352",
        "deletable" : false,
        "identifier" : "6E1A3B2C-91D4-4F5E-8A7B-0C9D8E7F6A5B",
        "kind" : "Bundled with Xcode",
        "platformIdentifier" : "com.apple.platform.watchsimulator",
        "runtimeIdentifier" : "com.apple.CoreSimulator.SimRuntime.watchOS-12-0",
        "sizeBytes" : 4211081216,
        "state" : "Ready",
        "version" : "12.0"
      }
    }
    """#

    /// The key and its `identifier` disagree → the whole listing is rejected.
    static let runtimeListJSONMismatchedKey = #"""
    {
      "08CA48EA-CFAF-41A4-B829-1AD1F1866837" : {
        "deletable" : true,
        "identifier" : "6E1A3B2C-91D4-4F5E-8A7B-0C9D8E7F6A5B",
        "sizeBytes" : 8067000161,
        "version" : "27.0"
      }
    }
    """#

    /// An option-injection attempt in place of a UUID → the whole listing is rejected.
    static let runtimeListJSONInjectedIdentifier = #"""
    {
      "--all" : {
        "deletable" : true,
        "identifier" : "--all",
        "sizeBytes" : 1
      }
    }
    """#

    /// simctl output that is not JSON (e.g. an error printed on stdout).
    static let simctlGarbage = "An error was encountered processing the command (domain=NSPOSIXErrorDomain, code=2)"

    /// A device without a UDID → the whole listing is rejected.
    static let devicesJSONMissingUDID = #"""
    { "devices" : { "com.apple.CoreSimulator.SimRuntime.iOS-27-0" : [ { "state" : "Shutdown", "name" : "iPhone" } ] } }
    """#

    /// A lower-case UDID (not canonical) → the whole listing is rejected.
    static let devicesJSONLowercaseUDID = #"""
    { "devices" : { "com.apple.CoreSimulator.SimRuntime.iOS-27-0" : [ { "udid" : "a47cd2c9-0c68-4140-a0b1-925934040ad2", "state" : "Shutdown", "name" : "iPhone", "isAvailable" : true } ] } }
    """#

    // MARK: - docker system df

    static let dockerSystemDF = """
    TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE
    Images          7         2         16.43GB   11.63GB (70%)
    Containers      3         1         115.2kB   98.3kB (85%)
    Local Volumes   3         1         2.052GB   1.947GB (94%)
    Build Cache     41        0         3.11GB    3.11GB

    """

    /// Nothing to reclaim.
    static let dockerSystemDFEmpty = """
    TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE
    Images          0         0         0B        0B
    Containers      0         0         0B        0B
    Local Volumes   0         0         0B        0B
    Build Cache     0         0         0B        0B

    """

    /// Unexpected header (a future format) → rejected.
    static let dockerSystemDFUnknownHeader = """
    TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE   SHARED
    Images          7         2         16.43GB   11.63GB       1GB

    """

    /// What the docker CLI prints (on stderr, exit 1) when the daemon is not running.
    static let dockerDaemonDownStderr = "Cannot connect to the Docker daemon at unix:///Users/me/.docker/run/docker.sock. Is the docker daemon running?"

    // MARK: - docker system df -v

    static let dockerSystemDFVerbose = """
    Images space usage:

    REPOSITORY                TAG       IMAGE ID       CREATED        SIZE      SHARED SIZE   UNIQUE SIZE   CONTAINERS
    postgres                  16        3b1d2c4e5f60   3 weeks ago    432.1MB   74.8MB        357.3MB       1
    <none>                    <none>    9a8b7c6d5e4f   2 months ago   1.21GB    0B            1.21GB        0

    Containers space usage:

    CONTAINER ID   IMAGE         COMMAND                  LOCAL VOLUMES   SIZE      CREATED        STATUS                    NAMES
    4f5e6d7c8b9a   postgres:16   "docker-entrypoint.s…"   1               63B       3 weeks ago    Up 2 hours                db
    1a2b3c4d5e6f   node:20       "docker-entrypoint.s…"   0               98.3kB    5 weeks ago    Exited (0) 5 weeks ago    old_builder

    Local Volumes space usage:

    VOLUME NAME                                                        LINKS     SIZE
    pgdata                                                             1         105.2MB
    old_pgdata                                                         0         1.85GB
    3f1c9e0a7b2d4c6e8f0a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e   0         97.4MB

    Build cache usage: 3.11GB

    CACHE ID       CACHE TYPE     SIZE      CREATED        LAST USED      USAGE     SHARED
    k2j3h4g5f6d7   regular        1.02GB    2 months ago   2 months ago   3         false

    """

    // MARK: - docker image ls --format '{{json .}}'

    static let dockerImageListJSON = """
    {"Containers":"N/A","CreatedAt":"2026-09-10 10:12:44 +0530 IST","CreatedSince":"3 weeks ago","Digest":"\\u003cnone\\u003e","ID":"3b1d2c4e5f60","Repository":"postgres","SharedSize":"N/A","Size":"432MB","Tag":"16","UniqueSize":"N/A","VirtualSize":"432.1MB"}
    {"Containers":"N/A","CreatedAt":"2026-08-01 09:00:00 +0530 IST","CreatedSince":"2 months ago","Digest":"\\u003cnone\\u003e","ID":"9a8b7c6d5e4f","Repository":"\\u003cnone\\u003e","SharedSize":"N/A","Size":"1.21GB","Tag":"\\u003cnone\\u003e","UniqueSize":"N/A","VirtualSize":"1.21GB"}
    {"Containers":"N/A","CreatedAt":"2026-07-15 18:30:00 +0530 IST","CreatedSince":"2 months ago","Digest":"\\u003cnone\\u003e","ID":"0f1e2d3c4b5a","Repository":"\\u003cnone\\u003e","SharedSize":"N/A","Size":"356MB","Tag":"\\u003cnone\\u003e","UniqueSize":"N/A","VirtualSize":"356MB"}
    {"Containers":"N/A","CreatedAt":"2026-06-02 12:00:00 +0530 IST","CreatedSince":"4 months ago","Digest":"\\u003cnone\\u003e","ID":"77aa88bb99cc","Repository":"node","SharedSize":"N/A","Size":"1.1GB","Tag":"20","UniqueSize":"N/A","VirtualSize":"1.1GB"}

    """

    /// Expected dangling estimate: the UNIQUE SIZE of the one dangling, container-less image in
    /// `dockerSystemDFVerbose` (review M4: never the logical image size).
    static let dockerDanglingBytes: Int64 = 1_210_000_000

    static let dockerImageListNotJSON = """
    REPOSITORY   TAG       IMAGE ID       CREATED        SIZE
    postgres     16        3b1d2c4e5f60   3 weeks ago    432MB

    """

    // MARK: - docker ps -a --filter status=exited --format '{{json .}}'

    static let dockerExitedContainersJSON = """
    {"Command":"\\"docker-entrypoint.s…\\"","CreatedAt":"2026-08-28 14:02:11 +0530 IST","ID":"1a2b3c4d5e6f","Image":"node:20","Labels":"","LocalVolumes":"0","Mounts":"","Names":"old_builder","Networks":"bridge","Ports":"","RunningFor":"5 weeks ago","Size":"0B","State":"exited","Status":"Exited (0) 5 weeks ago"}
    {"Command":"\\"/bin/sh -c 'npm t…\\"","CreatedAt":"2026-09-20 08:15:00 +0530 IST","ID":"6f5e4d3c2b1a","Image":"node:20","Labels":"","LocalVolumes":"0","Mounts":"","Names":"test_runner","Networks":"bridge","Ports":"","RunningFor":"12 days ago","Size":"0B","State":"exited","Status":"Exited (1) 12 days ago"}

    """

    // MARK: - docker volume ls -f dangling=true --format '{{json .}}'

    static let dockerDanglingVolumesJSON = """
    {"Availability":"N/A","Driver":"local","Group":"N/A","Labels":"","Links":"N/A","Mountpoint":"/var/lib/docker/volumes/old_pgdata/_data","Name":"old_pgdata","Scope":"local","Size":"N/A","Status":"N/A"}
    {"Availability":"N/A","Driver":"local","Group":"N/A","Labels":"com.docker.volume.anonymous=","Links":"N/A","Mountpoint":"/var/lib/docker/volumes/3f1c9e0a7b2d4c6e8f0a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e/_data","Name":"3f1c9e0a7b2d4c6e8f0a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e","Scope":"local","Size":"N/A","Status":"N/A"}

    """

    /// A volume that `system df -v` reports as still linked (pgdata) and one df -v does not list at all.
    static let dockerDanglingVolumesJSONDisagreeing = """
    {"Driver":"local","Name":"pgdata","Scope":"local"}
    {"Driver":"local","Name":"ghost_volume","Scope":"local"}

    """

    /// An option-injection attempt as a volume name → the whole listing is rejected.
    static let dockerDanglingVolumesJSONInjected = """
    {"Driver":"local","Name":"--force","Scope":"local"}

    """

    // MARK: - ollama list

    static let ollamaList = """
    NAME                                                 ID              SIZE      MODIFIED
    llama3.2:latest                                      a80c4f17acd5    2.0 GB    3 weeks ago
    qwen2.5-coder:7b                                     2b0496514337    4.7 GB    2 months ago
    library/mistral:7b-instruct-q4_0                     f974a74358d6    4.1 GB    5 months ago
    hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:Q4_K_M    3f3a4c1d9e2b    807 MB    About an hour ago

    """

    /// The model names `ollamaList` may offer (the hf.co one has upper-case letters → skipped).
    static let ollamaOfferedNames = ["llama3.2:latest", "qwen2.5-coder:7b", "library/mistral:7b-instruct-q4_0"]

    static let ollamaListEmpty = """
    NAME    ID    SIZE    MODIFIED

    """

    /// What `ollama list` prints when the Ollama app is not running (stderr, exit 1).
    static let ollamaNotRunningStderr = "Error: could not connect to ollama app, is it running?"

    /// A row whose size does not parse → the whole listing is rejected.
    static let ollamaListMalformedRow = """
    NAME               ID              SIZE      MODIFIED
    llama3.2:latest    a80c4f17acd5    huge      3 weeks ago

    """

    /// An injection attempt as a model name → never offered.
    static let ollamaListInjectedName = """
    NAME               ID              SIZE      MODIFIED
    --help             a80c4f17acd5    2.0 GB    3 weeks ago
    ../../etc:latest   2b0496514337    4.7 GB    2 months ago

    """
}

// MARK: - Suite


/// Parser and inspector tests for the Milestone 4 command clients, driven by `CommandFixtures` and
/// `FakeCommandRunner` only (no real command ever runs). Register with `await CommandClientTests.runAll()`.
struct CommandClientTests {
    static func rule(_ id: String, tier: Tier, inspector: InspectorID, tool: String, args: [String], pre: [Precondition]) -> Rule {
        Rule(id: id, category: .developer, tier: tier, title: id, explanation: "x", whatYouLose: "x", howItRegenerates: "x",
             discovery: .inspector(inspector), allowRoots: [], preconditions: pre,
             action: .command(CommandSpec(tool: tool, arguments: args)))
    }

    @MainActor
    static func runAll() async {
        await TestSuite.run("CommandClients: parsers") {
            let home = "/Users/me"
            let devices = try unwrap(SimctlClient.parseDevices(json: CommandFixtures.devicesJSON(home: home)))
            try TestSuite.assertEqual(devices.count, 3)
            try TestSuite.assertTrue(devices.allSatisfy { $0.dataPath?.hasPrefix("/Users/me/Library") == true }, "\(devices)")
            try TestSuite.assertEqual(SimctlClient.parseDevices(json: CommandFixtures.unavailableDevicesJSON(home: home))?.count, 2)
            try TestSuite.assertEqual(SimctlClient.parseDevices(json: CommandFixtures.unavailableDevicesJSONEmpty)?.count, 0)
            try TestSuite.assertTrue(SimctlClient.parseDevices(json: CommandFixtures.devicesJSONMissingUDID) == nil)
            try TestSuite.assertTrue(SimctlClient.parseDevices(json: CommandFixtures.devicesJSONLowercaseUDID) == nil)
            try TestSuite.assertTrue(SimctlClient.parseDevices(json: CommandFixtures.simctlGarbage) == nil)
            let runtimes = try unwrap(SimctlClient.parseRuntimes(json: CommandFixtures.runtimeListJSON))
            try TestSuite.assertEqual(runtimes.filter(\.deletable).map(\.identifier), [CommandFixtures.deletableRuntimeID])
            try TestSuite.assertEqual(runtimes.first { $0.deletable }?.sizeBytes, 8067000161)
            try TestSuite.assertTrue(SimctlClient.parseRuntimes(json: CommandFixtures.runtimeListJSONMismatchedKey) == nil)
            try TestSuite.assertTrue(SimctlClient.parseRuntimes(json: CommandFixtures.runtimeListJSONInjectedIdentifier) == nil)

            let df = try unwrap(DockerClient.parseSystemDF(CommandFixtures.dockerSystemDF))
            try TestSuite.assertEqual(df.images?.reclaimableBytes, 11_630_000_000)
            try TestSuite.assertEqual(df.containers?.reclaimableBytes, 98_300)
            try TestSuite.assertEqual(df.buildCache?.reclaimableBytes, 3_110_000_000)
            try TestSuite.assertEqual(df.buildCache?.total, 41)
            try TestSuite.assertTrue(DockerClient.parseSystemDF(CommandFixtures.dockerSystemDFEmpty) != nil)
            try TestSuite.assertTrue(DockerClient.parseSystemDF(CommandFixtures.dockerSystemDFUnknownHeader) == nil)
            let vols = try unwrap(DockerClient.parseVolumeUsage(CommandFixtures.dockerSystemDFVerbose))
            try TestSuite.assertEqual(vols.map(\.name).count, 3)
            try TestSuite.assertEqual(vols.first { $0.name == "old_pgdata" }?.sizeBytes, 1_850_000_000)
            let images = try unwrap(DockerClient.parseImages(CommandFixtures.dockerImageListJSON))
            try TestSuite.assertEqual(images.filter(\.isDangling).count, 2)
            try TestSuite.assertTrue(DockerClient.parseImages(CommandFixtures.dockerImageListNotJSON) == nil)
            try TestSuite.assertEqual(DockerClient.parseContainers(CommandFixtures.dockerExitedContainersJSON)?.map(\.names), ["old_builder", "test_runner"])
            try TestSuite.assertEqual(DockerClient.parseVolumeNames(CommandFixtures.dockerDanglingVolumesJSON)?.count, 2)
            try TestSuite.assertTrue(DockerClient.parseVolumeNames(CommandFixtures.dockerDanglingVolumesJSONInjected) == nil)

            let ollama = try unwrap(OllamaClient.parseList(CommandFixtures.ollamaList))
            try TestSuite.assertEqual(ollama.models.map(\.name), CommandFixtures.ollamaOfferedNames)
            try TestSuite.assertEqual(ollama.models.first?.sizeBytes, 2_000_000_000)
            try TestSuite.assertEqual(ollama.skippedNames.count, 1)
            try TestSuite.assertEqual(OllamaClient.parseList(CommandFixtures.ollamaListEmpty)?.models.count, 0)
            try TestSuite.assertTrue(OllamaClient.parseList(CommandFixtures.ollamaListMalformedRow) == nil)
            try TestSuite.assertEqual(OllamaClient.parseList(CommandFixtures.ollamaListInjectedName)?.models.count, 0)
        }

        await TestSuite.run("CommandClients: simulator inspectors") {
            let fixture = try FixtureBuilder()
            defer { fixture.cleanup() }
            let env = FakeEnvironment(fixture: fixture)
            env.commands.executables = ["xcrun": CommandFixtures.xcrunPath]
            env.commands.setResponse(CommandResult(exitCode: 0, stdout: CommandFixtures.devicesJSON(home: fixture.home), stderr: ""), for: SimctlClient.listDevicesArguments)
            env.commands.setResponse(CommandResult(exitCode: 0, stdout: CommandFixtures.unavailableDevicesJSON(home: fixture.home), stderr: ""), for: SimctlClient.listUnavailableDevicesArguments)
            env.commands.setResponse(CommandResult(exitCode: 0, stdout: CommandFixtures.runtimeListJSON, stderr: ""), for: SimctlClient.listRuntimesArguments)
            let base = "Library/Developer/CoreSimulator/Devices/"
            for udid in [CommandFixtures.staleUDID, CommandFixtures.freshUDID, CommandFixtures.bootedUDID, CommandFixtures.unavailableUDID1] {
                try fixture.file(base + udid + "/data/x", bytes: 5000)
                try fixture.file(base + udid + "/device.plist", bytes: 100)
            }
            let old = Date().addingTimeInterval(-200 * 86400)
            env.fileSystem.overrideStat(fixture.path(base + CommandFixtures.staleUDID), modificationDate: old)
            env.fileSystem.overrideStat(fixture.path(base + CommandFixtures.staleUDID + "/data"), modificationDate: old)
            env.fileSystem.overrideStat(fixture.path(base + CommandFixtures.staleUDID + "/device.plist"), modificationDate: old)
            env.fileSystem.overrideStat(fixture.path(base + CommandFixtures.bootedUDID), modificationDate: old)
            env.fileSystem.overrideStat(fixture.path(base + CommandFixtures.bootedUDID + "/data"), modificationDate: old)
            env.fileSystem.overrideStat(fixture.path(base + CommandFixtures.bootedUDID + "/device.plist"), modificationDate: old)

            let unavailable = rule("simulator.unavailable", tier: .green, inspector: .simulatorUnavailable, tool: "xcrun", args: ["simctl", "delete", "unavailable"], pre: [.simulatorIdle])
            let out1 = await SimctlUnavailableInspector().discover(rule: unavailable, environment: env.environment)
            try TestSuite.assertEqual(out1.status, .ok)
            try TestSuite.assertEqual(out1.candidates.count, 1)
            try TestSuite.assertEqual(out1.candidates[0].kind, .commandItem(argument: nil))
            try TestSuite.assertEqual(out1.candidates[0].sizePaths, [fixture.path(base + CommandFixtures.unavailableUDID1)])

            let stale = rule("simulator.devices.stale", tier: .yellow, inspector: .simulatorDevices, tool: "xcrun", args: ["simctl", "delete", "{ITEM}"], pre: [.simulatorIdle, .olderThan(days: 90)])
            let out2 = await SimctlDevicesInspector().discover(rule: stale, environment: env.environment)
            try TestSuite.assertEqual(out2.status, .ok)
            try TestSuite.assertEqual(out2.candidates.map(\.kind), [.commandItem(argument: CommandFixtures.staleUDID)])
            // Missing precondition → fail closed.
            let noPre = rule("simulator.devices.stale", tier: .yellow, inspector: .simulatorDevices, tool: "xcrun", args: ["simctl", "delete", "{ITEM}"], pre: [])
            let out2b = await SimctlDevicesInspector().discover(rule: noPre, environment: env.environment)
            try TestSuite.assertTrue(out2b.candidates.isEmpty)

            let runtimes = rule("simulator.runtimes", tier: .yellow, inspector: .simulatorRuntimes, tool: "xcrun", args: ["simctl", "runtime", "delete", "{ITEM}"], pre: [.simulatorIdle])
            let out3 = await SimctlRuntimesInspector().discover(rule: runtimes, environment: env.environment)
            try TestSuite.assertEqual(out3.candidates.map(\.kind), [.commandItem(argument: CommandFixtures.deletableRuntimeID)])
            try TestSuite.assertEqual(out3.candidates.first?.reportedBytes, 8067000161)
            // Every call was read-only.
            try TestSuite.assertTrue(env.commands.invocations.allSatisfy { CommandAllowList.matches(tool: "xcrun", arguments: $0.arguments, purpose: .readOnly) })

            // Tool failure → unavailable.
            env.commands.setResponse(CommandResult(exitCode: 1, stdout: "", stderr: "x"), for: SimctlClient.listDevicesArguments)
            let out4 = await SimctlDevicesInspector().discover(rule: stale, environment: env.environment)
            if case .unavailable = out4.status {} else { throw TestError("expected unavailable \(out4.status)") }
        }

        await TestSuite.run("CommandClients: docker + ollama inspectors") {
            let fixture = try FixtureBuilder()
            defer { fixture.cleanup() }
            let env = FakeEnvironment(fixture: fixture)
            env.commands.executables = ["docker": CommandFixtures.dockerPath, "ollama": CommandFixtures.ollamaPath]
            env.commands.setResponse(CommandResult(exitCode: 0, stdout: CommandFixtures.dockerSystemDF, stderr: ""), for: DockerClient.systemDFArguments)
            env.commands.setResponse(CommandResult(exitCode: 0, stdout: CommandFixtures.dockerSystemDFVerbose, stderr: ""), for: DockerClient.systemDFVerboseArguments)
            env.commands.setResponse(CommandResult(exitCode: 0, stdout: CommandFixtures.dockerImageListJSON, stderr: ""), for: DockerClient.imageListArguments)
            env.commands.setResponse(CommandResult(exitCode: 0, stdout: CommandFixtures.dockerExitedContainersJSON, stderr: ""), for: DockerClient.exitedContainersArguments)
            env.commands.setResponse(CommandResult(exitCode: 0, stdout: CommandFixtures.dockerDanglingVolumesJSON, stderr: ""), for: DockerClient.danglingVolumesArguments)
            env.commands.setResponse(CommandResult(exitCode: 0, stdout: CommandFixtures.ollamaList, stderr: ""), for: OllamaClient.listArguments)
            let pre: [Precondition] = [.dockerDaemonReachable]
            let cases: [(String, Tier, [String])] = [
                ("docker.danglingImages", .green, ["image", "prune", "-f"]),
                ("docker.buildCache", .green, ["builder", "prune", "-f"]),
                ("docker.unusedImages", .yellow, ["image", "prune", "-a", "-f"]),
                ("docker.stoppedContainers", .yellow, ["container", "prune", "-f"]),
                ("docker.volumes", .red, ["volume", "rm", "{ITEM}"]),
            ]
            for (id, tier, args) in cases {
                let r = rule(id, tier: tier, inspector: .dockerSystem, tool: "docker", args: args, pre: pre)
                let out = await DockerSystemInspector().discover(rule: r, environment: env.environment)
                try TestSuite.assertEqual(out.status, .ok, id)
            }
            let vr = rule("docker.volumes", tier: .red, inspector: .dockerSystem, tool: "docker", args: ["volume", "rm", "{ITEM}"], pre: pre)
            env.commands.setResponse(CommandResult(exitCode: 0, stdout: CommandFixtures.dockerDanglingVolumesJSONDisagreeing, stderr: ""), for: DockerClient.danglingVolumesArguments)
            let disagree = await DockerSystemInspector().discover(rule: vr, environment: env.environment)
            try TestSuite.assertEqual(disagree.candidates.count, 0)
            try TestSuite.assertTrue(env.commands.invocations.allSatisfy { CommandAllowList.matches(tool: "docker", arguments: $0.arguments, purpose: .readOnly) || CommandAllowList.matches(tool: "ollama", arguments: $0.arguments, purpose: .readOnly) })

            env.processes.names.append("ollama")
            let or = rule("ai.ollama", tier: .yellow, inspector: .ollamaModels, tool: "ollama", args: ["rm", "{ITEM}"], pre: [])
            let o = await OllamaModelsInspector().discover(rule: or, environment: env.environment)
            try TestSuite.assertEqual(o.candidates.map(\.kind), CommandFixtures.ollamaOfferedNames.map { .commandItem(argument: $0) })
        }
    }

    static func unwrap<T>(_ value: T?, file: StaticString = #file, line: UInt = #line) throws -> T {
        guard let value else { throw TestError("unexpected nil at \(file):\(line)") }
        return value
    }
}
