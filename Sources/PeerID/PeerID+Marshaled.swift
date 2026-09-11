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
import Multibase

/// - MARK: Marshaled Imports and Exports
extension PeerID {

    /// PeerID Marshalling (protobufs) Related Errors
    public enum MarshallingError: Error, Equatable, Sendable, CustomStringConvertible {
        /// Marshalled payload doesn't contain any valid keys
        case emptyMarshalledData
        /// This PeerID doesn't have a Private Key to Marshal
        case noPrivateKeyAvailable
        /// This PeerID doesn't have a Public Key to Marshal
        case noPublicKeyAvailable
        /// The id embedded in the marshaled payload doesn't match the id derived from its key material
        case idMismatch

        public var description: String {
            switch self {
            case .emptyMarshalledData:
                return "PeerID.MarshallingError: marshaled payload doesn't contain any valid keys"
            case .noPrivateKeyAvailable:
                return "PeerID.MarshallingError: this PeerID doesn't have a private key to marshal"
            case .noPublicKeyAvailable:
                return "PeerID.MarshallingError: this PeerID doesn't have a public key to marshal"
            case .idMismatch:
                return
                    "PeerID.MarshallingError: the embedded id doesn't match the id derived from the key material"
            }
        }
    }

    /// Inits a `PeerID` from a marshaled `PeerID` string
    /// - Parameters:
    ///   - marshaledPeerID: The marshalled PeerID string
    ///   - base: The base in which the data is encoded, unless the string provided is a valid Multibase string
    ///
    /// - Note: `base` can be left `nil` if the marshaledPeerID String is `Multibase` compliant (includes the multibase prefix) otherwise, you must specify the ecoded base of the string...
    public init(marshaledPeerID: String, base: BaseEncoding? = nil) throws {
        let marshaledData: Data
        if let base = base {
            marshaledData = Data(try BaseEncoding.decode(marshaledPeerID, as: base))
        } else {
            marshaledData = Data(try BaseEncoding.decode(marshaledPeerID).bytes)
        }
        try self.init(marshaledPeerID: marshaledData)
    }

    /// Inits a `PeerID` from a marshaled `PeerID`
    /// - Parameter data: The marshalled PeerID (serialized protobuf)
    ///
    /// - Note: If the marshaled payload carries a non-empty `id`, it's validated against the id
    ///   derived from the key material and a ``MarshallingError/idMismatch`` is thrown on mismatch.
    public init(marshaledPeerID data: Data) throws {
        // Attempt to instantiate a PeerIdProto with the raw, marshaled, data
        let protoPeerID = try PeerIdProto(serializedBytes: data)

        // Ensure the marshaled data included at least a public or private key
        guard protoPeerID.hasPubKey || protoPeerID.hasPrivKey else {
            throw MarshallingError.emptyMarshalledData
        }

        // If we have a private key, instantiate the PeerID via the private key, otherwise the public key
        if protoPeerID.hasPrivKey {
            try self.init(marshaledPrivateKey: protoPeerID.privKey)
        } else {
            try self.init(marshaledPublicKey: protoPeerID.pubKey)
        }

        // Validate the embedded id (when present) against the id derived from the key material
        if !protoPeerID.id.isEmpty, !self.matchesID(protoPeerID.id.byteArray) {
            throw MarshallingError.idMismatch
        }
    }

    /// Inits a `PeerID` from a marshaled public key string
    public init(marshaledPublicKey str: String, base: BaseEncoding) throws {
        try self.init(keyPair: LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: str, base: base))
    }

    /// Inits a `PeerID` from a marshaled public key
    public init(marshaledPublicKey key: Data) throws {
        try self.init(keyPair: LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: key))
    }

    /// Inits a `PeerID` from a marshaled private key string
    public init(marshaledPrivateKey str: String, base: BaseEncoding) throws {
        try self.init(keyPair: LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: str, base: base))
    }

    /// Inits a `PeerID` from a marshaled private key
    public init(marshaledPrivateKey data: Data) throws {
        try self.init(keyPair: LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: data))
    }

    /// Returns a protocol-buffers encoded version of the id, public key and, if `includingPrivateKey` is set to `true`, the private key.
    /// - Throws: ``MarshallingError/noPublicKeyAvailable`` if this is an id-only PeerID with no underlying key pair.
    public func marshal(includingPrivateKey: Bool = false) throws -> [UInt8] {
        guard let keyPair = self.keyPair else {
            throw MarshallingError.noPublicKeyAvailable
        }
        var pid = PeerIdProto()
        pid.id = Data(self.id)
        pid.pubKey = try keyPair.publicKey.marshal()
        if includingPrivateKey, let privKey = keyPair.privateKey {
            pid.privKey = try privKey.marshal()
        }
        return try pid.serializedData().byteArray
    }

    /// Returns the protobuf-marshaled private key (`KeyType` + raw key data, not wrapped in a `PeerIdProto`).
    public func marshalPrivateKey() throws -> [UInt8] {
        guard let privKey = self.keyPair?.privateKey else {
            throw MarshallingError.noPrivateKeyAvailable
        }
        return try privKey.marshal().byteArray
    }

    /// Returns the protobuf-marshaled public key (`KeyType` + raw key data, not wrapped in a `PeerIdProto`).
    public func marshalPublicKey() throws -> [UInt8] {
        guard let pubKey = self.keyPair?.publicKey else {
            throw MarshallingError.noPublicKeyAvailable
        }
        return try pubKey.marshal().byteArray
    }
}

extension Data {
    var byteArray: [UInt8] {
        Array(self)
    }
}
