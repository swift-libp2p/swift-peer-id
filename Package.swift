// swift-tools-version:6.1
//===----------------------------------------------------------------------===//
//
// This source file is part of the swift-libp2p open source project
//
// Copyright (c) 2022-2026 swift-libp2p project authors
// Licensed under MIT
//
// See LICENSE for license information
// See CONTRIBUTORS for the list of swift-libp2p project authors
//
// SPDX-License-Identifier: MIT
//
//===----------------------------------------------------------------------===//

import PackageDescription

let package = Package(
    name: "swift-peer-id",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "PeerID",
            targets: ["PeerID"]
        )
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/swift-libp2p/swift-libp2p-crypto.git", .upToNextMinor(from: "0.3.0")),
        .package(url: "https://github.com/swift-libp2p/swift-multihash.git", .upToNextMinor(from: "0.3.0")),
        .package(url: "https://github.com/swift-libp2p/swift-multibase.git", .upToNextMinor(from: "0.3.0")),
        .package(url: "https://github.com/swift-libp2p/swift-multicodec.git", .upToNextMinor(from: "0.3.0")),
        .package(url: "https://github.com/swift-libp2p/swift-cid.git", .upToNextMinor(from: "0.3.0")),
        .package(url: "https://github.com/apple/swift-protobuf.git", .upToNextMajor(from: "1.33.3")),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "PeerID",
            dependencies: [
                .product(name: "LibP2PCrypto", package: "swift-libp2p-crypto"),
                .product(name: "Multihash", package: "swift-multihash"),
                .product(name: "Multibase", package: "swift-multibase"),
                .product(name: "Multicodec", package: "swift-multicodec"),
                .product(name: "CID", package: "swift-cid"),
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
            exclude: [
                "Protobufs/PeerIdProto.proto"
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "PeerIDTests",
            dependencies: [
                "PeerID",
                .product(name: "LibP2PCrypto", package: "swift-libp2p-crypto"),
                .product(name: "Multihash", package: "swift-multihash"),
                .product(name: "Multibase", package: "swift-multibase"),
                .product(name: "Multicodec", package: "swift-multicodec"),
                .product(name: "CID", package: "swift-cid"),
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
            swiftSettings: swiftSettings
        ),
    ]
)

var swiftSettings: [SwiftSetting] {
    [
        .enableUpcomingFeature("MemberImportVisibility"),
        .enableUpcomingFeature("ExistentialAny"),
    ]
}
