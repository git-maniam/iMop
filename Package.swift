// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "iMop",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(
            name: "iMop",
            targets: ["iMop"]
        ),
        .executable(
            name: "iMopTests",
            targets: ["iMopTests"]
        )
    ],
    targets: [
        .target(
            name: "iMopCore",
            path: "Sources/iMopCore"
        ),
        .executableTarget(
            name: "iMop",
            dependencies: ["iMopCore"],
            path: "Sources/iMop",
            resources: [
                .process("Resources")
            ]
        ),
        .executableTarget(
            name: "iMopTests",
            dependencies: ["iMopCore"],
            path: "Tests/iMopTests"
        )
    ]
)
