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

/// - MARK: PEM Imports and Exports
extension PeerID {
    public convenience init(pem: String, password: String?) throws {
        try self.init(keyPair: LibP2PCrypto.Keys.KeyPair(pem: pem, password: password))
    }

    public enum ExportType {
        case publicPEMString
        case privatePEMString(encryptedWithPassword: String)
        case unencrypredPrivatePEMString
    }

    /// Exports the KeyPair as  PEM structured String. Private Keys can be encrypted with a password before export.
    public func exportKeyPair(as exportType: ExportType) throws -> String {
        guard let keyPair = self.keyPair else {
            throw NSError(domain: "No Underlying Key Pair to Export", code: 0, userInfo: nil)
        }
        switch exportType {
        case .publicPEMString:
            return try keyPair.publicKey.exportPublicKeyPEMString(withHeaderAndFooter: true)
        case .unencrypredPrivatePEMString:
            guard keyPair.privateKey != nil else {
                throw NSError(domain: "No Private Key to Export", code: 0, userInfo: nil)
            }
            return try keyPair.exportPrivatePEMString(withHeaderAndFooter: true)
        case .privatePEMString(let password):
            guard !password.isEmpty else {
                throw NSError(domain: "Password shouldn't be empty", code: 0, userInfo: nil)
            }
            return try keyPair.exportEncryptedPrivatePEMString(withPassword: password)
        }
    }
}
