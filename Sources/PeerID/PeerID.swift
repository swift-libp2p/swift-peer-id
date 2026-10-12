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

public import CID
import Foundation
public import LibP2PCrypto
import Multibase
import Multicodec
public import Multihash

/// - Reference: https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md#how-keys-are-encoded-and-messages-signed
public struct PeerID: Sendable {

    /// General PeerID Errors
    public enum Errors: Error, Equatable, Sendable, CustomStringConvertible {

        /// Invalid CID Codec for PeerID Instantiation
        case invalidCIDCodec(expected: String, received: String)

        /// The multihash uses a hash function other than `sha2-256` or `identity`
        case unsupportedMultihash(algorithm: String)

        /// The `identity` multihash doesn't contain a valid, canonically encoded, inlinable public key
        case invalidEmbeddedPublicKey

        public var description: String {
            switch self {
            case .invalidCIDCodec(let expected, let received):
                return "PeerID.Errors: invalid CID codec (expected \(expected), received \(received))"
            case .unsupportedMultihash(let algorithm):
                return "PeerID.Errors: unsupported multihash '\(algorithm)' (expected 'sha2-256' or 'identity')"
            case .invalidEmbeddedPublicKey:
                return "PeerID.Errors: the identity multihash doesn't contain a valid, canonically encoded public key"
            }
        }
    }

    /// Marshaled public keys of this size or smaller are inlined in the PeerID using the `identity` multihash
    /// - Reference: https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md#peer-ids
    internal static let maxInlineKeyLength = 42

    /// The keys ID is the multihash of its marshaled public key
    /// - Note: Marshaled keys of `maxInlineKeyLength` bytes or less are inlined using the `identity` multihash, larger keys are hashed using `sha2-256`
    public let multihash: Multihash
    public let keyPair: LibP2PCrypto.Keys.KeyPair?

    /// The canonical id used for equality and hashing.
    ///
    /// For an `.identity` multihash that inlines a marshaled public key (embedded Ed25519 /
    /// Secp256k1 PeerIDs) this is the SHA-256 multihash of that key; for every other PeerID it is
    /// the raw `id`. Normalizing to this form lets an embedded-key PeerID compare and hash equal to
    /// its traditional (`Qm…`) SHA-256 equivalent.
    internal let canonicalID: [UInt8]

    /// Returns the ID of this PeerID as bytes
    public var id: [UInt8] { multihash.value }

    /// Returns the ID of this PeerID as bytes
    @available(*, deprecated, renamed: "id")
    public var bytes: [UInt8] { id }

    /// Returns the PeerID's id as a base58 string (multihash/CIDv0).
    public var b58String: String {
        self.id.asString(base: .base58btc)
    }

    /// Returns the PeerID's id as a hex string.
    public var hexString: String {
        self.id.asString(base: .base16)
    }

    /// A base32 encoded, version 1 CID, representing this PeerID
    public var cidString: String {
        (try? CID(version: .v1, codec: .libp2p_key, multihash: self.multihash).toBaseEncodedString(.base32)) ?? ""
    }

    public enum PeerType: Sendable, Hashable {
        case idOnly
        case isPublic
        case isPrivate
    }

    /// A simple way of checking a PeerID's type (id only, public key & id, or private key, public key and id)
    public var type: PeerType {
        if self.keyPair?.privateKey != nil {
            return .isPrivate
        } else if self.keyPair?.publicKey != nil {
            return .isPublic
        } else {
            return .idOnly
        }
    }

    /// The single initializer every other initializer collapses to
    private init(multihash: Multihash, keyPair: LibP2PCrypto.Keys.KeyPair?) {
        self.multihash = multihash
        self.keyPair = keyPair
        self.canonicalID = PeerID.canonicalID(for: multihash)
    }

    /// Generates a Public/Private `KeyPair` of the specified type and initializes a `PeerID` with it (defaults to RSA 2048 bits)
    public init(_ keyType: LibP2PCrypto.Keys.KeyPairType = .rsa(bits: .b2048)) throws {
        try self.init(keyPair: LibP2PCrypto.Keys.generateKeyPair(keyType))
    }

    /// Initializes a `PeerID` using an existing Public/Private `KeyPair`
    public init(keyPair: LibP2PCrypto.Keys.KeyPair) throws {
        self.init(multihash: try keyPair.multihash(), keyPair: keyPair)
    }

    /// Inits a `PeerID` from a hex encoded multihash
    /// - Supports embedded (identity multihash) Ed25519 & Secp256k1 Public Keys
    public init(fromHexID hex: String) throws {
        try self.init(fromBytesID: BaseEncoding.decode(hex, as: .base16))
    }

    /// Inits a `PeerID` from a binary multihash
    /// - Supports embedded (identity multihash) Ed25519 & Secp256k1 Public Keys
    /// - Throws: ``Errors/unsupportedMultihash(algorithm:)`` if the multihash isn't `sha2-256` or `identity`,
    ///   ``Errors/invalidEmbeddedPublicKey`` if an `identity` multihash doesn't inline a valid public key
    public init(fromBytesID bytes: [UInt8]) throws {
        try self.init(validating: Multihash(bytes))
    }

    /// Inits a `PeerID` from a string
    ///
    /// Per the spec, strings beginning with `Qm` or `1` are treated as raw base58btc encoded multihashes,
    /// everything else is parsed as a multibase encoded CIDv1 using the `libp2p-key` codec.
    /// - Supports embedded (identity multihash) Ed25519 & Secp256k1 Public Keys
    /// - Reference: https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md#decoding
    public init(cid: String) throws {
        if cid.hasPrefix("Qm") || cid.hasPrefix("1") {
            try self.init(fromBytesID: BaseEncoding.decode(cid, as: .base58btc))
        } else {
            try self.init(cid: CID(cid))
        }
    }

    /// Inits a `PeerID` from a v0 dag-pb or v1 libp2p-key CID
    /// - Supports embedded (identity multihash) Ed25519 & Secp256k1 Public Keys
    public init(cid: CID) throws {
        let isV0 = cid.version == .v0 && cid.codec == .dag_pb
        guard isV0 || cid.codec == .libp2p_key else {
            throw Errors.invalidCIDCodec(expected: "'v0 dag-pb' or 'v1 libp2p-key'", received: "\(cid.codec)")
        }
        try self.init(validating: cid.multihash)
    }

    /// Validates the multihash per the spec (`sha2-256`, or an `identity` multihash inlining a public key)
    private init(validating multihash: Multihash) throws {
        switch multihash.algorithm {
        case .sha2_256:
            self.init(multihash: multihash, keyPair: nil)
        case .identity:
            try self.init(identityMultihash: multihash)
        default:
            throw Errors.unsupportedMultihash(algorithm: multihash.hashName ?? "0x\(String(multihash.code, radix: 16))")
        }
    }

    /// Recovers the public key inlined in an `identity` multihash.
    ///
    /// The inlined key must be no larger than ``maxInlineKeyLength`` and must re-derive the exact same multihash.
    /// This rejects keys that should have been hashed (RSA / ECDSA) and non-canonical encodings (ex: an uncompressed
    /// Secp256k1 key or a protobuf with unknown fields), which would otherwise produce a PeerID whose `id` differs
    /// from the one it was decoded from.
    private init(identityMultihash multihash: Multihash) throws {
        guard multihash.digest.count <= PeerID.maxInlineKeyLength,
            let keyPair = try? LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: Data(multihash.digest)),
            let derived = try? keyPair.multihash(),
            derived == multihash
        else {
            throw Errors.invalidEmbeddedPublicKey
        }
        self.init(multihash: multihash, keyPair: keyPair)
    }

    /// Returns the PeerID's id as a self-describing CIDv1 in Base32 (RFC 0001)
    /// return self-describing String representation
    /// in default format from RFC 0001: https://github.com/libp2p/specs/pull/209
    public func toString() -> String {
        self.cidString
    }

    /// Computes the ``canonicalID`` for an arbitrary multihash. See ``canonicalID``.
    internal static func canonicalID(for multihash: Multihash) -> [UInt8] {
        guard multihash.algorithm == .identity else { return multihash.value }
        return Multihash(hashing: multihash.digest, with: .sha2_256).value
    }

    /// This method checks each PeerID's multihash for embedded public keys (via the use of the identity protocol) and converts them to the traditional SHA256 versions before comparing the underlying digests.
    /// - Allows for comparisons between Traditional PeerIDs and Embedded Public Key PeerIDs.
    internal func isEquivalent(to other: PeerID) -> Bool {
        self.canonicalID == other.canonicalID
    }

    /// Returns `true` if the provided id refers to the same peer as this PeerID, accounting for the
    /// embedded (identity) vs. traditional (SHA-256) multihash representations of the same key.
    internal func matchesID(_ other: [UInt8]) -> Bool {
        if self.id == other { return true }
        guard let otherMH = try? Multihash(other) else { return false }
        return self.canonicalID == PeerID.canonicalID(for: otherMH)
    }

    /// Returns `true` if this PeerID was derived from the provided public key (go-libp2p's `MatchesPublicKey`)
    /// - Note: Like `==`, an embedded (identity) PeerID matches the SHA-256 form of the same key and vice versa
    public func matches(publicKey: any CommonPublicKey) -> Bool {
        guard let mh = try? publicKey.multihash() else { return false }
        return self.canonicalID == PeerID.canonicalID(for: mh)
    }

    /// Returns the PeerID as a SHA256 Base58 Encoding
    /// - This is equivalent to calling `.b58String` for all keys except embedded Ed25519 / Secp256k1 Public Keys
    /// - For Embedded Public Keys, this method will strip the public key from the ID and return the traditional SHA256 encoded value (Qm prefix style)
    /// - Note: This method never throws, it's marked as `throws` for source compatibility
    public func traditionalB58String() throws -> String {
        PeerID.canonicalID(for: self.multihash).asString(base: .base58btc)
    }

    /// Returns the Peer ID as a printable string without the Qm prefix.
    ///
    /// Example: <peer.ID xxxxxx>
    public func toPrint() -> String {
        self.description
    }
}

extension PeerID: CustomStringConvertible {
    public var description: String {
        let pid = self.b58String
        return "<peer.ID \(dropPrefix(pid).prefix(6))>"
    }

    public var shortDescription: String {
        let pid = self.b58String
        return String(dropPrefix(pid).prefix(6))
    }

    public var debugDescription: String {
        """
            Peer ID
            id: \(id.asString(base: .base58btc))
            pubKey: \(keyPair?.publicKey.asString(base: .base64Pad) ?? "NIL")
            privKey: \(keyPair?.privateKey?.asString(base: .base64Pad) ?? "NIL")
        """
    }

    private func dropPrefix(_ pid: String) -> String.SubSequence {
        var skip = 0
        if pid.hasPrefix("Qm") {
            skip = 2
        } else if pid.hasPrefix("12D3KooW") {
            skip = 8
        }
        return pid.dropFirst(skip)
    }
}
