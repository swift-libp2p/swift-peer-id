// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "swift-peer-id",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "PeerID",
            targets: ["PeerID"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/swift-libp2p/swift-libp2p-crypto.git", .upToNextMinor(from: "0.1.1")),
        .package(url: "https://github.com/swift-libp2p/swift-multihash.git", .upToNextMajor(from: "0.0.1")),
        .package(url: "https://github.com/swift-libp2p/swift-cid.git", .upToNextMajor(from: "0.0.1")),
        .package(url: "https://github.com/apple/swift-protobuf.git", .upToNextMajor(from: "1.12.0"))
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "PeerID",
            dependencies: [
                .product(name: "LibP2PCrypto", package: "swift-libp2p-crypto"),
                .product(name: "Multihash", package: "swift-multihash"),
                .product(name: "CID", package: "swift-cid"),
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
            resources: [
              .copy("Protobufs/PeerIdProto.proto")
            ]),
        .testTarget(
            name: "PeerIDTests",
            dependencies: ["PeerID"]),
    ]
)
