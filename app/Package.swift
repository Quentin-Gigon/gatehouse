// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "Gatehouse",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(name: "Gatehouse", path: "Sources/Gatehouse"),
    ]
)
