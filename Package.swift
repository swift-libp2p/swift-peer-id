// swift-tools-version:5.5
//===----------------------------------------------------------------------===//
//
// This source file is part of the swift-libp2p open source project
//
// Copyright (c) 2022-2025 swift-libp2p project authors
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
        .macOS(.v10_15),
        .iOS(.v13),
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
        .package(url: "https://github.com/swift-libp2p/swift-libp2p-crypto.git", .upToNextMinor(from: "0.1.1")),
        .package(url: "https://github.com/swift-libp2p/swift-multihash.git", .upToNextMinor(from: "0.0.1")),
        .package(url: "https://github.com/swift-libp2p/swift-cid.git", .upToNextMinor(from: "0.0.1")),
        .package(
            name: "SwiftProtobuf",
            url: "https://github.com/apple/swift-protobuf.git",
            .upToNextMajor(from: "1.12.0")
        ),
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
                .product(name: "SwiftProtobuf", package: "SwiftProtobuf"),
            ],
            resources: [
                .copy("Protobufs/PeerIdProto.proto")
            ]
        ),
        .testTarget(
            name: "PeerIDTests",
            dependencies: ["PeerID"]
        ),
    ]
)
