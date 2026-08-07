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

import Foundation

extension PeerID: Equatable {
    public static func == (lhs: PeerID, rhs: PeerID) -> Bool {
        lhs.id == rhs.id || lhs.isEquivalent(to: rhs)
    }
    public static func == (lhs: [UInt8], rhs: PeerID) -> Bool {
        lhs == rhs.id
    }
    public static func == (lhs: Data, rhs: PeerID) -> Bool {
        lhs.byteArray == rhs.id
    }
}

extension PeerID: Hashable {
    /// Hashes on the ``canonicalID`` so that an embedded-key PeerID and its traditional SHA-256
    /// equivalent (which compare equal via `==`) also produce the same hash value.
    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.canonicalID)
    }
}
