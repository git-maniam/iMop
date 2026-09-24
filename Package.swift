// swift-tools-version: 5.10
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
        )
    ],
    targets: [
        .executableTarget(
            name: "iMop",
            path: "Sources"
        ),
        .testTarget(
            name: "iMopTests",
            dependencies: ["iMop"],
            path: "Tests/iMopTests"
        )
    ]
)
