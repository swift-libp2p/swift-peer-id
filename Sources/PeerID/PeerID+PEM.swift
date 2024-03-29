//
//  PeerID+PEM.swift
//  
//
//  Created by Brandon Toms on 9/23/22.
//

import LibP2PCrypto
import Foundation

/// - MARK: PEM Imports and Exports
public extension PeerID {
    convenience init(pem: String, password: String?) throws {
      try self.init(keyPair: LibP2PCrypto.Keys.KeyPair(pem: pem, password: password))
    }

    enum ExportType {
        case publicPEMString
        case privatePEMString(encryptedWithPassword:String)
        case unencrypredPrivatePEMString
    }

    /// Exports the KeyPair as  PEM structured String. Private Keys can be encrypted with a password before export.
    func exportKeyPair(as exportType:ExportType) throws -> String {
        guard let keyPair = self.keyPair else { throw NSError(domain: "No Underlying Key Pair to Export", code: 0, userInfo: nil) }
        switch exportType {
        case .publicPEMString:
            return try keyPair.publicKey.exportPublicKeyPEMString(withHeaderAndFooter: true)
        case .unencrypredPrivatePEMString:
            guard keyPair.privateKey != nil else { throw NSError(domain: "No Private Key to Export", code: 0, userInfo: nil) }
            return try keyPair.exportPrivatePEMString(withHeaderAndFooter: true)
        case .privatePEMString(let password):
            guard !password.isEmpty else { throw NSError(domain: "Password shouldn't be empty", code: 0, userInfo: nil) }
            return try keyPair.exportEncryptedPrivatePEMString(withPassword: password)
        }
    }
}
