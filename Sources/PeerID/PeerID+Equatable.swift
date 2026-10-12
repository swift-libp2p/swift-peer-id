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

public import Foundation

/// - Note: Equality accounts for the embedded (identity) vs. traditional (SHA-256) multihash representations of the same key,
///   so `12D3KooW…` and its `Qm…` equivalent compare (and hash) equal.
extension PeerID: Equatable {
    public static func == (lhs: PeerID, rhs: PeerID) -> Bool {
        lhs.isEquivalent(to: rhs)
    }
    public static func == (lhs: [UInt8], rhs: PeerID) -> Bool {
        rhs.matchesID(lhs)
    }
    public static func == (lhs: Data, rhs: PeerID) -> Bool {
        rhs.matchesID(Array(lhs))
    }
}

extension PeerID: Hashable {
    /// Hashes on the ``canonicalID`` so that an embedded-key PeerID and its traditional SHA-256
    /// equivalent (which compare equal via `==`) also produce the same hash value.
    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.canonicalID)
    }
}
