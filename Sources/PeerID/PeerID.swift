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

import LibP2PCrypto
import Foundation
import Multihash
import CID

/// - Reference: https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md#how-keys-are-encoded-and-messages-signed
public class PeerID {
    /// The keys ID is the SHA-256 multihash of its public key
    /// - Note: The public key is a protobuf encoding containing a type and the DER encoding of the PKCS SubjectPublicKeyInfo.
    public let id:[UInt8]
    public let keyPair:LibP2PCrypto.Keys.KeyPair?
    
    /// Returns the PeerID's id as a base58 string (multihash/CIDv0).
    public lazy var b58String:String = {
        self.id.asString(base: .base58btc)
    }()
    
    /// Returns the PeerID's id as a hex string.
    public lazy var hexString:String = {
        self.id.asString(base: .base16)
    }()
    
    /// A base32 encoded, version 1 CID, representing this PeerID
    public lazy var cidString:String = {
        //const cid = new CID(1, 'libp2p-key', this.id, 'base32')
        //this._idCIDString = cid.toBaseEncodedString('base32')
        (try? CID(version: .v1, codec: .libp2p_key, hash: self.id).toBaseEncodedString(.base32)) ?? ""
    }()
    
    public enum PeerType {
        case idOnly
        case isPublic
        case isPrivate
    }
    
    /// A simple way of checking a PeerID's type (id only, public key & id, or private key, public key and id)
    public lazy var type:PeerType = {
        if self.keyPair?.privateKey != nil { return .isPrivate }
        else if self.keyPair?.publicKey != nil { return .isPublic }
        else { return .idOnly }
    }()
    
    /// Returns the id of this PeerID as bytes
    public var bytes:[UInt8] {
        return id
    }
    
    /// Generates a Public/Private `KeyPair` of the specified type and initializes a `PeerID` with it (defaults to RSA 2048 bits)
    public init(_ keyType:LibP2PCrypto.Keys.KeyPairType = .RSA(bits: .B2048)) throws {
        let keyPair = try LibP2PCrypto.Keys.generateKeyPair(keyType)
        
        self.id = try keyPair.rawID()
        self.keyPair = keyPair
    }
    
    /// Initializes a `PeerID` using an existing Public/Private `KeyPair`
    public init(keyPair:LibP2PCrypto.Keys.KeyPair) throws {
        self.id = try keyPair.rawID()
        self.keyPair = keyPair
    }
    
    //init(publicKey:RawPublicKey) throws {
    //    let kp = LibP2PCrypto.Keys.KeyPair(
    //}
    
    //init(privateKey:RawPrivateKey) throws {
    //    let kp = LibP2PCrypto.Keys.KeyPair(
    //}
    
    /// Inits a `PeerID` based solely on an ID value with no underlying `KeyPair`
    public init(fromHexID hex:String) throws {
        self.id = try Multihash(hexString: hex).value //or digest
        self.keyPair = nil
    }
    
    public convenience init(fromBytesID bytes:[UInt8]) throws {
        if let mh = try? Multihash(bytes), mh.algorithm == .identity {
            try self.init(marshaledPublicKey: Data(mh.digest!))
        } else {
            try self.init(fromBytesIDInternal: bytes)
        }
    }
    
    /// Inits a `PeerID` based solely on an ID value with no underlying `KeyPair`
    internal init(fromBytesIDInternal bytes:[UInt8]) throws {
        self.id = bytes
        self.keyPair = nil
    }
    
    /// Inits a `PeerID` from a v0 dag-pb or v1 libp2p-key CID complient string
    public convenience init(cid:String) throws {
        try self.init(cid: CID(cid))
    }
    
    /// Inits a `PeerID` from a v0 dag-pb or v1 libp2p-key CID
    public init(cid:CID) throws {
        guard cid.codec == .libp2p_key || cid.codec == .dag_pb else {
            throw NSError(domain: "Invalid CID codec \(cid.codec), must be either 'v0 dag-pb' or 'v1 libp2p-key'", code: 0, userInfo: nil)
        }
        self.id = cid.multihash.value
        self.keyPair = nil
    }
    
    /// Returns the PeerID's id as a self-describing CIDv1 in Base32 (RFC 0001)
    /// return self-describing String representation
    /// in default format from RFC 0001: https://github.com/libp2p/specs/pull/209
    public func toString() -> String {
        self.cidString
    }
    
    /// Returns the Peer ID as a printable string without the Qm prefix.
    ///
    /// Example: <peer.ID xxxxxx>
    public func toPrint() -> String {
        self.description
    }
    
    private func toBase64Pad(_ buf:[UInt8]) -> String {
        buf.asString(base: .base64Pad)
    }
}

extension PeerID:CustomStringConvertible {
    public var description: String {
        let pid = self.b58String
        var skip = 0
        if pid.hasPrefix("Qm") {
            skip = 2
        } else if pid.hasPrefix("12D3KooW") {
            skip = 8
        }
        return "<peer.ID \(pid.dropFirst(skip).prefix(6))>"
    }
    
    public var shortDescription: String {
        let pid = self.b58String
        if pid.hasPrefix("Qm") {
            return String(pid.dropFirst(2).prefix(6))
        } else if pid.hasPrefix("12D3KooW") {
            return String(pid.dropFirst(8).prefix(6))
        } else {
            return String(pid.prefix(6))
        }
    }
    
    public var debugDescription: String {
        return """
            Peer ID
            id: \(id.asString(base: .base58btc))
            pubKey: \(keyPair?.publicKey.asString(base: .base64Pad) ?? "NIL")
            privKey: \(keyPair?.privateKey?.asString(base: .base64Pad) ?? "NIL")
        """
    }
}

private extension Array where Element == UInt8 {
    var base64Pad:String {
        self.asString(base: .base64Pad)
    }
}

//public func computeDigest(rawPubKey:Data) -> Data {
//    if rawPubKey.count <= 42 {
//        return Multihash(raw: rawPubKey, hashedWith: .identity)
//    } else {
//        return rawPubKey.hash()
//    }
//}
