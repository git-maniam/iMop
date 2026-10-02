import Foundation

// Read-only discovery for the Docker command rules (spec §6.4): `docker.danglingImages`,
// `docker.buildCache`, `docker.unusedImages`, `docker.stoppedContainers` and `docker.volumes`.
//
// Only the docker CLI's read-only listings are run (through `SafeCleanEnvironment.commands`, purpose
// `.readOnly`). iMop never starts Docker: when the daemon is not reachable every listing fails and
// the rules report "unavailable". `docker.diskImage` (Advisory) is a later milestone.

// MARK: - docker client

/// Read-only docker CLI queries and their defensive parsers.
public struct DockerClient: Sendable {
    public static let tool = "docker"
    public static let systemDFArguments = ["system", "df"]
    public static let systemDFVerboseArguments = ["system", "df", "-v"]
    public static let imageListArguments = ["image", "ls", "--format", CommandAllowList.dockerJSONFormat]
    public static let exitedContainersArguments = ["ps", "-a", "--filter", "status=exited", "--format", CommandAllowList.dockerJSONFormat]
    public static let danglingVolumesArguments = ["volume", "ls", "-f", "dangling=true", "--format", CommandAllowList.dockerJSONFormat]
    /// Read-only listing timeout (`system df -v` can be slow on large installations).
    static let timeout: TimeInterval = 60

    /// One row of the `docker system df` summary table.
    public struct DiskUsageRow: Sendable, Hashable {
        public let total: Int
        public let active: Int
        public let sizeBytes: Int64
        public let reclaimableBytes: Int64
    }

    /// `docker system df` summary, keyed by row type.
    public struct DiskUsage: Sendable, Hashable {
        public let images: DiskUsageRow?
        public let containers: DiskUsageRow?
        public let localVolumes: DiskUsageRow?
        public let buildCache: DiskUsageRow?
    }

    public struct Image: Sendable, Hashable {
        public let repository: String
        public let tag: String
        public let id: String
        public let sizeBytes: Int64?

        /// Untagged image (`<none>:<none>`) — what `docker image prune -f` removes.
        public var isDangling: Bool { repository == "<none>" && tag == "<none>" }
    }

    public struct Container: Sendable, Hashable {
        public let id: String
        public let names: String
        public let status: String
    }

    /// One image of the `docker system df -v` "Images space usage" table.
    public struct ImageUsage: Sendable, Hashable {
        public let repository: String
        public let tag: String
        public let id: String
        public let sizeBytes: Int64
        public let sharedBytes: Int64
        /// Bytes only this image uses — what removing it can actually free.
        public let uniqueBytes: Int64
        public let containers: Int

        /// Untagged image (`<none>:<none>`) — what `docker image prune -f` removes.
        public var isDangling: Bool { repository == "<none>" && tag == "<none>" }
    }

    /// One volume of the `docker system df -v` "Local Volumes space usage" table.
    public struct VolumeUsage: Sendable, Hashable {
        public let name: String
        public let links: Int
        public let sizeBytes: Int64
    }

    let environment: SafeCleanEnvironment

    public init(environment: SafeCleanEnvironment) {
        self.environment = environment
    }

    private func query(_ arguments: [String]) async -> Result<String, CommandDiscovery.Failure> {
        await CommandDiscovery.readOnly(Self.tool, arguments, timeout: Self.timeout, environment: environment)
    }

    func diskUsage() async -> Result<DiskUsage, CommandDiscovery.Failure> {
        switch await query(Self.systemDFArguments) {
        case .failure(let failure): return .failure(failure)
        case .success(let text):
            guard let usage = Self.parseSystemDF(text) else { return .failure(.failed("Could not read Docker's disk usage")) }
            return .success(usage)
        }
    }

    func volumeUsage() async -> Result<[VolumeUsage], CommandDiscovery.Failure> {
        switch await query(Self.systemDFVerboseArguments) {
        case .failure(let failure): return .failure(failure)
        case .success(let text):
            guard let volumes = Self.parseVolumeUsage(text) else { return .failure(.failed("Could not read Docker's volume sizes")) }
            return .success(volumes)
        }
    }

    func imageUsage() async -> Result<[ImageUsage], CommandDiscovery.Failure> {
        switch await query(Self.systemDFVerboseArguments) {
        case .failure(let failure): return .failure(failure)
        case .success(let text):
            guard let images = Self.parseImageUsage(text) else { return .failure(.failed("Could not read Docker's image sizes")) }
            return .success(images)
        }
    }

    func images() async -> Result<[Image], CommandDiscovery.Failure> {
        switch await query(Self.imageListArguments) {
        case .failure(let failure): return .failure(failure)
        case .success(let text):
            guard let images = Self.parseImages(text) else { return .failure(.failed("Could not read the Docker image list")) }
            return .success(images)
        }
    }

    func exitedContainers() async -> Result<[Container], CommandDiscovery.Failure> {
        switch await query(Self.exitedContainersArguments) {
        case .failure(let failure): return .failure(failure)
        case .success(let text):
            guard let containers = Self.parseContainers(text) else { return .failure(.failed("Could not read the Docker container list")) }
            return .success(containers)
        }
    }

    func danglingVolumes() async -> Result<[String], CommandDiscovery.Failure> {
        switch await query(Self.danglingVolumesArguments) {
        case .failure(let failure): return .failure(failure)
        case .success(let text):
            guard let names = Self.parseVolumeNames(text) else { return .failure(.failed("Could not read the Docker volume list")) }
            return .success(names)
        }
    }

    // MARK: Parsers

    static let dfRowLabels: [(label: String, key: String)] = [
        ("Images", "images"), ("Containers", "containers"), ("Local Volumes", "localVolumes"), ("Build Cache", "buildCache"),
    ]

    /// Parses the `docker system df` table:
    ///
    ///     TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE
    ///     Images          5         2         16.43GB   11.63GB (70%)
    ///
    /// SAFETY-DECISION: all or nothing — `nil` without the expected header, for an unknown or
    /// duplicated row, or for any value that does not parse.
    @_spi(FixtureTesting)
    public static func parseSystemDF(_ text: String) -> DiskUsage? {
        let lines = text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        guard let header = lines.first else { return nil }
        let headerTokens = header.split(whereSeparator: \.isWhitespace).map { $0.uppercased() }
        guard headerTokens == ["TYPE", "TOTAL", "ACTIVE", "SIZE", "RECLAIMABLE"] else { return nil }
        var rows: [String: DiskUsageRow] = [:]
        for line in lines.dropFirst() {
            guard let (label, key) = dfRowLabels.first(where: { line.hasPrefix($0.label + " ") }) else { return nil }
            let tokens = line.dropFirst(label.count).split(whereSeparator: \.isWhitespace).map(String.init)
            // TOTAL ACTIVE SIZE RECLAIMABLE [(NN%)]
            guard tokens.count == 4 || tokens.count == 5,
                  let total = Int(tokens[0]), total >= 0,
                  let active = Int(tokens[1]), active >= 0,
                  let size = CommandDiscovery.parseHumanSize(tokens[2]),
                  let reclaimable = CommandDiscovery.parseHumanSize(tokens[3]) else { return nil }
            if tokens.count == 5 {
                guard tokens[4].hasPrefix("("), tokens[4].hasSuffix("%)") else { return nil }
            }
            guard rows[key] == nil else { return nil }
            rows[key] = DiskUsageRow(total: total, active: active, sizeBytes: size, reclaimableBytes: reclaimable)
        }
        guard !rows.isEmpty else { return nil }
        return DiskUsage(images: rows["images"], containers: rows["containers"],
                         localVolumes: rows["localVolumes"], buildCache: rows["buildCache"])
    }

    /// Parses the "Local Volumes space usage" section of `docker system df -v`:
    ///
    ///     Local Volumes space usage:
    ///
    ///     VOLUME NAME   LINKS     SIZE
    ///     pgdata        0         245.1MB
    ///
    /// SAFETY-DECISION: all or nothing — `nil` when the section or its header is missing, a name is
    /// not a valid volume name, a volume is listed twice, or a value does not parse.
    @_spi(FixtureTesting)
    public static func parseVolumeUsage(_ text: String) -> [VolumeUsage]? {
        let lines = text.components(separatedBy: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
        guard let sectionIndex = lines.firstIndex(where: { $0.lowercased() == "local volumes space usage:" }) else { return nil }
        var index = sectionIndex + 1
        while index < lines.count, lines[index].isEmpty { index += 1 }
        guard index < lines.count else { return nil }
        let headerTokens = lines[index].split(whereSeparator: \.isWhitespace).map { $0.uppercased() }
        guard headerTokens == ["VOLUME", "NAME", "LINKS", "SIZE"] else { return nil }
        index += 1
        var volumes: [VolumeUsage] = []
        var seen = Set<String>()
        while index < lines.count, !lines[index].isEmpty {
            let tokens = lines[index].split(whereSeparator: \.isWhitespace).map(String.init)
            guard tokens.count == 3,
                  CommandItemKind.dockerVolumeName.accepts(tokens[0]),
                  let links = Int(tokens[1]), links >= 0,
                  let size = CommandDiscovery.parseHumanSize(tokens[2]),
                  seen.insert(tokens[0]).inserted else { return nil }
            volumes.append(VolumeUsage(name: tokens[0], links: links, sizeBytes: size))
            index += 1
        }
        return volumes
    }

    /// Parses the "Images space usage" section of `docker system df -v`:
    ///
    ///     Images space usage:
    ///
    ///     REPOSITORY   TAG       IMAGE ID       CREATED        SIZE      SHARED SIZE   UNIQUE SIZE   CONTAINERS
    ///     <none>       <none>    9a8b7c6d5e4f   2 months ago   1.21GB    0B            1.21GB        0
    ///
    /// CREATED contains spaces, so the four size/count columns are read from the right.
    /// SAFETY-DECISION: all or nothing — `nil` when the section or its header is missing or any row
    /// does not parse.
    @_spi(FixtureTesting)
    public static func parseImageUsage(_ text: String) -> [ImageUsage]? {
        let lines = text.components(separatedBy: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
        guard let sectionIndex = lines.firstIndex(where: { $0.lowercased() == "images space usage:" }) else { return nil }
        var index = sectionIndex + 1
        while index < lines.count, lines[index].isEmpty { index += 1 }
        guard index < lines.count else { return nil }
        let headerTokens = lines[index].split(whereSeparator: \.isWhitespace).map { $0.uppercased() }
        guard headerTokens == ["REPOSITORY", "TAG", "IMAGE", "ID", "CREATED", "SIZE", "SHARED", "SIZE", "UNIQUE", "SIZE", "CONTAINERS"] else {
            return nil
        }
        index += 1
        var images: [ImageUsage] = []
        while index < lines.count, !lines[index].isEmpty {
            let tokens = lines[index].split(whereSeparator: \.isWhitespace).map(String.init)
            guard tokens.count >= 8,
                  !tokens[2].isEmpty,
                  let size = CommandDiscovery.parseHumanSize(tokens[tokens.count - 4]),
                  let shared = CommandDiscovery.parseHumanSize(tokens[tokens.count - 3]),
                  let unique = CommandDiscovery.parseHumanSize(tokens[tokens.count - 2]),
                  let containers = Int(tokens[tokens.count - 1]), containers >= 0 else { return nil }
            images.append(ImageUsage(repository: tokens[0], tag: tokens[1], id: tokens[2], sizeBytes: size,
                                     sharedBytes: shared, uniqueBytes: unique, containers: containers))
            index += 1
        }
        return images
    }

    /// Parses `docker image ls --format '{{json .}}'` (one object per line).
    @_spi(FixtureTesting)
    public static func parseImages(_ text: String) -> [Image]? {
        guard let objects = CommandDiscovery.jsonLines(text) else { return nil }
        var images: [Image] = []
        for object in objects {
            guard let repository = object["Repository"] as? String,
                  let tag = object["Tag"] as? String,
                  let id = object["ID"] as? String, !id.isEmpty else { return nil }
            let size = (object["Size"] as? String).flatMap(CommandDiscovery.parseHumanSize)
            images.append(Image(repository: repository, tag: tag, id: id, sizeBytes: size))
        }
        return images
    }

    /// Parses `docker ps -a --filter status=exited --format '{{json .}}'`.
    @_spi(FixtureTesting)
    public static func parseContainers(_ text: String) -> [Container]? {
        guard let objects = CommandDiscovery.jsonLines(text) else { return nil }
        var containers: [Container] = []
        for object in objects {
            guard let id = object["ID"] as? String, !id.isEmpty,
                  let names = object["Names"] as? String else { return nil }
            containers.append(Container(id: id, names: names, status: (object["Status"] as? String) ?? ""))
        }
        return containers
    }

    /// Parses `docker volume ls -f dangling=true --format '{{json .}}'` into volume names.
    ///
    /// SAFETY-DECISION: all or nothing — a line without a `Name`, a name that is not a valid volume
    /// name, or a duplicated name makes the whole listing untrusted (`nil`).
    @_spi(FixtureTesting)
    public static func parseVolumeNames(_ text: String) -> [String]? {
        guard let objects = CommandDiscovery.jsonLines(text) else { return nil }
        var names: [String] = []
        var seen = Set<String>()
        for object in objects {
            guard let name = object["Name"] as? String, CommandItemKind.dockerVolumeName.accepts(name),
                  seen.insert(name).inserted else { return nil }
            names.append(name)
        }
        return names
    }
}

// MARK: - dockerSystem inspector

/// Inspector `dockerSystem`, shared by every Docker command rule. It dispatches on the rule id and
/// only emits items when the rule is acted on by exactly the command written for that id.
public struct DockerSystemInspector: Inspector {
    public init() {}

    public var id: InspectorID { .dockerSystem }

    /// Rule id → the exact action command (arguments after `docker`).
    static let expectedCommands: [String: [String]] = [
        "docker.danglingImages": ["image", "prune", "-f"],
        "docker.buildCache": ["builder", "prune", "-f"],
        "docker.unusedImages": ["image", "prune", "-a", "-f"],
        "docker.stoppedContainers": ["container", "prune", "-f"],
        "docker.volumes": ["volume", "rm", CommandSpec.itemToken],
    ]
    static let requiredPreconditions = ["dockerDaemonReachable"]
    static let undoNote = "This cannot be undone. Docker will re-download what it needs."

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        guard let expected = Self.expectedCommands[rule.id],
              CommandDiscovery.ruleMatches(rule, tool: DockerClient.tool, arguments: expected,
                                           required: Self.requiredPreconditions) else {
            return Self.unavailable("This rule does not match its Docker command")
        }
        let client = DockerClient(environment: environment)
        switch rule.id {
        case "docker.danglingImages": return await danglingImages(rule: rule, client: client)
        case "docker.buildCache": return await buildCache(rule: rule, client: client)
        case "docker.unusedImages": return await unusedImages(rule: rule, client: client)
        case "docker.stoppedContainers": return await stoppedContainers(rule: rule, client: client)
        case "docker.volumes": return await volumes(rule: rule, client: client)
        default: return Self.unavailable("This rule does not match its Docker command")
        }
    }

    static func status(for failure: CommandDiscovery.Failure) -> String {
        switch failure {
        case .toolMissing: return "Docker is not installed"
        // SAFETY-DECISION: iMop never starts Docker; an unreachable daemon simply skips the rule.
        case .failed(let reason): return "Docker is not running or did not answer (\(reason)). iMop never starts Docker."
        }
    }

    static let none = InspectorOutput(candidates: [], status: .ok)

    static func unavailable(_ reason: String) -> InspectorOutput {
        InspectorOutput(candidates: [], status: .unavailable(reason))
    }

    /// One whole-command item (no argument) sized by Docker's own estimate.
    private func wholeCommand(label: String, displayName: String, bytes: Int64, notes: [String]) -> InspectorOutput {
        let candidate = DiscoveredCandidate(
            commandItem: nil, path: CommandDiscovery.informationalPath("docker", label), displayName: displayName,
            reportedBytes: max(0, bytes), notes: notes + [Self.undoNote])
        return InspectorOutput(candidates: [candidate], status: .ok)
    }

    // MARK: docker.danglingImages

    private func danglingImages(rule: Rule, client: DockerClient) async -> InspectorOutput {
        let estimate: DanglingEstimate
        switch await Self.danglingEstimate(client: client) {
        case .failure(let failure): return Self.unavailable(Self.status(for: failure))
        case .success(let value): estimate = value
        }
        guard estimate.count > 0 else { return Self.none }
        let notes = [
            "\(estimate.count) untagged (dangling) image\(estimate.count == 1 ? "" : "s"), not used by any tag or container.",
            "Estimated from the unique size Docker reports for each image; layers shared with other images are not freed and not counted.",
        ]
        return wholeCommand(label: "dangling images", displayName: "Dangling Docker images (\(estimate.count))",
                            bytes: estimate.bytes, notes: notes)
    }

    struct DanglingEstimate {
        let count: Int
        let bytes: Int64
    }

    /// Dangling images without containers and the sum of their UNIQUE sizes (`docker system df -v`).
    ///
    /// Spec §7 honesty (review M4): never an image's full (logical) size, which includes layers
    /// shared with other images that `docker image prune -f` does not free.
    static func danglingEstimate(client: DockerClient) async -> Result<DanglingEstimate, CommandDiscovery.Failure> {
        switch await client.imageUsage() {
        case .failure(let failure): return .failure(failure)
        case .success(let images):
            var seen = Set<String>()
            var bytes: Int64 = 0
            for image in images where image.isDangling && image.containers == 0 && seen.insert(image.id).inserted {
                bytes = CommandDiscovery.add(bytes, image.uniqueBytes)
            }
            return .success(DanglingEstimate(count: seen.count, bytes: bytes))
        }
    }

    // MARK: docker.buildCache

    private func buildCache(rule: Rule, client: DockerClient) async -> InspectorOutput {
        let usage: DockerClient.DiskUsage
        switch await client.diskUsage() {
        case .failure(let failure): return Self.unavailable(Self.status(for: failure))
        case .success(let value): usage = value
        }
        guard let row = usage.buildCache else {
            return Self.unavailable("Docker did not report its build cache")
        }
        guard row.reclaimableBytes > 0 else { return Self.none }
        let notes = [
            "Build cache: \(CommandDiscovery.formatBytes(row.sizeBytes)) in \(row.total) entr\(row.total == 1 ? "y" : "ies").",
            "Estimated reclaimable as reported by `docker system df`.",
        ]
        return wholeCommand(label: "build cache", displayName: "Docker build cache", bytes: row.reclaimableBytes, notes: notes)
    }

    // MARK: docker.unusedImages

    private func unusedImages(rule: Rule, client: DockerClient) async -> InspectorOutput {
        let usage: DockerClient.DiskUsage
        switch await client.diskUsage() {
        case .failure(let failure): return Self.unavailable(Self.status(for: failure))
        case .success(let value): usage = value
        }
        guard let row = usage.images else {
            return Self.unavailable("Docker did not report its images")
        }
        let unused = max(0, row.total - row.active)
        guard unused > 0 || row.reclaimableBytes > 0 else { return Self.none }
        var notes = [
            "\(unused) of \(row.total) image\(row.total == 1 ? "" : "s") not used by any container.",
            "Removes every image without a container, including tagged images you pulled or built.",
        ]
        // Spec §7 honesty (review M4): the dangling images' space is already counted by
        // docker.danglingImages, so it is left out here and never added to the total twice.
        var bytes = row.reclaimableBytes
        switch await Self.danglingEstimate(client: client) {
        case .success(let dangling):
            bytes = max(0, bytes - dangling.bytes)
            notes.append("Also removes the dangling images listed separately; their space (\(CommandDiscovery.formatBytes(dangling.bytes))) is counted there, not here.")
        case .failure:
            notes.append("Also removes the dangling images listed separately.")
        }
        notes.append("Estimated reclaimable as reported by `docker system df`.")
        return wholeCommand(label: "unused images", displayName: "Unused Docker images (\(unused))", bytes: bytes, notes: notes)
    }

    // MARK: docker.stoppedContainers

    private func stoppedContainers(rule: Rule, client: DockerClient) async -> InspectorOutput {
        let containers: [DockerClient.Container]
        switch await client.exitedContainers() {
        case .failure(let failure): return Self.unavailable(Self.status(for: failure))
        case .success(let list): containers = list
        }
        let usage: DockerClient.DiskUsage
        switch await client.diskUsage() {
        case .failure(let failure): return Self.unavailable(Self.status(for: failure))
        case .success(let value): usage = value
        }
        guard let row = usage.containers else {
            return Self.unavailable("Docker did not report its containers")
        }
        let stopped = max(containers.count, row.total - row.active)
        guard stopped > 0 else { return Self.none }
        var notes = [
            "\(stopped) stopped container\(stopped == 1 ? "" : "s"). Files written inside a container (its writable layer) are lost.",
            "Also removes containers that were created but never started.",
        ]
        notes += containers.prefix(20).map { "• \($0.names) (\($0.status))" }
        if containers.count > 20 { notes.append("… and \(containers.count - 20) more") }
        notes.append("Estimated reclaimable as reported by `docker system df`.")
        return wholeCommand(label: "stopped containers", displayName: "Stopped Docker containers (\(stopped))", bytes: row.reclaimableBytes, notes: notes)
    }

    // MARK: docker.volumes (Red)

    private func volumes(rule: Rule, client: DockerClient) async -> InspectorOutput {
        let names: [String]
        switch await client.danglingVolumes() {
        case .failure(let failure): return Self.unavailable(Self.status(for: failure))
        case .success(let list): names = list
        }
        guard !names.isEmpty else { return Self.none }
        // SAFETY-DECISION (M4 integration): volumes hold databases (Red). Each volume is offered only
        // when `docker system df -v` ALSO lists it with zero links; if that cross-check cannot be made
        // (the listing fails or does not parse), the whole rule is unavailable instead of offering
        // volumes that could not be double-checked.
        let usage: [String: DockerClient.VolumeUsage]
        switch await client.volumeUsage() {
        case .failure(let failure): return Self.unavailable(Self.status(for: failure))
        case .success(let list): usage = Dictionary(list.map { ($0.name, $0) }, uniquingKeysWith: { first, _ in first })
        }

        var candidates: [DiscoveredCandidate] = []
        for name in names {
            var notes = [
                "Databases and other app data often live in Docker volumes.",
                "Not attached to any container right now (dangling), but its data is still there.",
            ]
            // SAFETY-DECISION: the two listings must agree. A volume `system df -v` does not list,
            // or lists as still linked to a container, is not offered.
            guard let entry = usage[name], entry.links == 0 else { continue }
            let bytes = entry.sizeBytes
            notes.append("Size reported by `docker system df -v`.")
            notes.append("This cannot be undone. The data in this volume is permanently deleted; Docker cannot re-download it.")
            candidates.append(DiscoveredCandidate(
                commandItem: name, path: CommandDiscovery.informationalPath("docker volume", name),
                displayName: "Docker volume \(name)", reportedBytes: bytes, notes: notes))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }
}
