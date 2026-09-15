// swift-tools-version:6.2
import PackageDescription

let package = Package(
    name: "TrafficInspectorCore",
    platforms: [
        .iOS(.v26),
        .macOS(.v13),
    ],
    products: [
        .library(name: "TrafficInspectorCore", targets: ["TrafficInspectorCore"]),
    ],
    targets: [
        .systemLibrary(
            name: "CSQLite",
            path: "ios/CSQLite",
            pkgConfig: "sqlite3",
            providers: [
                .apt(["libsqlite3-dev"]),
                .brew(["sqlite3"]),
            ]
        ),
        .target(
            name: "TrafficInspectorCore",
            dependencies: ["CSQLite"],
            path: "ios/Shared"
        ),
        .testTarget(
            name: "TrafficInspectorCoreTests",
            dependencies: ["TrafficInspectorCore"],
            path: "ios/Tests"
        ),
    ]
)
