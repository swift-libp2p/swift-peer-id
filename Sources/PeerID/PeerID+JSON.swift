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
import LibP2PCrypto
import Multibase

/// - MARK: JSON Imports and Exports
extension PeerID {

    /// PeerID JSON Related Errors
    public enum JSONError: Error, Equatable, Sendable, CustomStringConvertible {

        /// Invalid JSON Payload
        case invalidJSON

        /// The `id` in the JSON payload doesn't match the id derived from its key material
        case idMismatch

        /// The `pubKey` in the JSON payload doesn't match the public key derived from the `privKey`
        case publicKeyMismatch

        /// This PeerID doesn't have a Private Key to export
        case noPrivateKeyAvailable

        public var description: String {
            switch self {
            case .invalidJSON:
                return "PeerID.JSONError: invalid JSON payload"
            case .idMismatch:
                return "PeerID.JSONError: the provided id doesn't match the id derived from the key material"
            case .publicKeyMismatch:
                return "PeerID.JSONError: the provided public key doesn't match the one derived from the private key"
            case .noPrivateKeyAvailable:
                return "PeerID.JSONError: this PeerID doesn't have a private key to export"
            }
        }
    }

    /// An Internal PeerID struct to facilitate JSON Encoding and Decoding
    internal struct PeerIDJSON: Codable {

        /// base58 encoded string
        let id: String

        /// base64 encoded publicKey protobuf
        let pubKey: String?

        /// base64 encoded privateKey protobuf
        let privKey: String?
    }

    /// Initialize a PeerID from JSON data
    ///
    /// Expects a JSON object of the form
    /// ```
    /// {
    ///   obj.id: String - The multihash encoded in base58
    ///   obj.pubKey: String? - The public key in protobuf format, encoded in 'base64'
    ///   obj.privKey: String? - The private key in protobuf format, encoded in 'base64'
    /// }
    /// ```
    /// - Note: When key material is present, the `id` (and the `pubKey` when a `privKey` is also provided) must agree with it
    public init(fromJSON json: Data) throws {
        let data = try JSONDecoder().decode(PeerIDJSON.self, from: json)
        let providedID: [UInt8] = try BaseEncoding.decode(data.id, as: .base58btc)

        if let privKey = data.privKey {
            /// Private Key was provided. Init via the private key and derive both the public key and the ID
            try self.init(marshaledPrivateKey: privKey, base: .base64)
            if let pubKey = data.pubKey {
                let providedPubKey: [UInt8] = try BaseEncoding.decode(pubKey, as: .base64)
                guard try self.marshalPublicKey() == providedPubKey else { throw JSONError.publicKeyMismatch }
            }
        } else if let pubKey = data.pubKey {
            /// Only Public Key and ID Present, init via the public key and derive the ID
            try self.init(marshaledPublicKey: pubKey, base: .base64)
        } else {
            /// Only ID Present...
            try self.init(fromBytesID: providedID)
            return
        }

        /// The PeerID was derived from key material, ensure the provided `id` agrees with it
        guard self.matchesID(providedID) else { throw JSONError.idMismatch }
    }

    /// Exports our PeerID as a JSON object
    ///
    /// Returns a JSON object of the form
    /// ```
    /// {
    ///   id: String - The multihash encoded in base58
    ///   pubKey: String? - The public key in protobuf format, encoded in 'base64'
    ///   privKey: String? - The private key in protobuf format, encoded in 'base64'
    /// }
    /// ```
    /// - Throws: ``JSONError/noPrivateKeyAvailable`` if `includingPrivateKey` is `true` and this PeerID doesn't have a private key
    public func toJSON(includingPrivateKey: Bool = false) throws -> Data {
        var privKey: String? = nil
        if includingPrivateKey {
            guard let key = self.keyPair?.privateKey else { throw JSONError.noPrivateKeyAvailable }
            privKey = try key.marshal().asString(base: .base64)
        }

        let pidJSON = PeerIDJSON(
            id: self.b58String,
            pubKey: try self.keyPair?.publicKey.marshal().asString(base: .base64),
            privKey: privKey
        )

        return try JSONEncoder().encode(pidJSON)
    }

    /// Exports our PeerID as a JSON object
    ///
    /// Returns a JSON object as a String
    /// ```
    /// {
    ///   id: String - The multihash encoded in base58
    ///   pubKey: String? - The public key in protobuf format, encoded in 'base64'
    ///   privKey: String? - The private key in protobuf format, encoded in 'base64'
    /// }
    /// ```
    public func toJSONString(includingPrivateKey: Bool = false) throws -> String? {
        try String(data: self.toJSON(includingPrivateKey: includingPrivateKey), encoding: .utf8)
    }
}
