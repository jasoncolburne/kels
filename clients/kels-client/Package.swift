// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "KelsClient",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(
            name: "KelsCore",
            targets: ["KelsCore"]
        ),
    ],
    targets: [
        .systemLibrary(
            name: "LibKels",
            path: "Sources/LibKels"
        ),
        .target(
            name: "KelsCore",
            dependencies: ["LibKels"],
            path: "Sources/KelsCore"
        ),
    ]
)
