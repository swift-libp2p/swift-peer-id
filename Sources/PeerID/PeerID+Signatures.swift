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
import LibP2PCrypto

/// - MARK: PeerID Signatures and Verification Methods
extension PeerID {
    // Signs data using this PeerID's private key. This signature can then be verified by a remote peer using this PeerID's public key
    public func signature(for msg: Data) throws -> Data {
        guard let priv = keyPair?.privateKey else {
            throw NSError(
                domain:
                    "A private key is required for generating signature and this PeerID doesn't contain a private key.",
                code: 0,
                userInfo: nil
            )
        }

        return try priv.sign(message: msg)
    }

    // Using this PeerID's public key, this method checks to see if the signature data was in fact signed by this peer and is a valid signature for the expected data
    public func isValidSignature(_ signature: Data, for expectedData: Data) throws -> Bool {
        guard let pub = keyPair?.publicKey else {
            throw NSError(
                domain:
                    "A public key is required for verifying signatures and this PeerID doesn't contain a public key.",
                code: 0,
                userInfo: nil
            )
        }

        return try pub.verify(signature: signature, for: expectedData)
    }
}
