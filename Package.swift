// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SwiftAuditCanary",
    platforms: [
        .iOS(.v14),
        .macOS(.v11)
    ],
    products: [
        .library(name: "SwiftAuditCanary", targets: ["SwiftAuditCanary"])
    ],
    targets: [
        .target(name: "SwiftAuditCanary", path: "Sources/SwiftAuditCanary")
    ]
)
