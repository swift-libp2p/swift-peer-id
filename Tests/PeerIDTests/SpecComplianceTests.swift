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

import CID
import Foundation
import LibP2PCrypto
import Multibase
import Multicodec
import Multihash
import SwiftProtobuf
import Testing

@testable import PeerID

/// libp2p peer-id spec compliance
/// - Reference: https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md
@Suite("Spec Compliance Tests")
struct SpecComplianceTests {

    // MARK: Spec Test Vectors

    @Test func testEd25519SpecVector() throws {
        let peerID = try PeerID(marshaledPrivateKey: TestFixtures.hex(SpecVectors.Ed25519.privateKey))
        #expect(try peerID.marshalPublicKey().asString(base: .base16) == SpecVectors.Ed25519.publicKey)
        #expect(peerID.b58String == SpecVectors.Ed25519.peerID)
        #expect(peerID.multihash.algorithm == .identity)

        let recovered = try PeerID(cid: SpecVectors.Ed25519.peerID)
        #expect(recovered.type == .isPublic)
        #expect(try recovered.marshalPublicKey().asString(base: .base16) == SpecVectors.Ed25519.publicKey)
    }

    // MARK: Multihash Validation

    /// Only `sha2-256` and `identity` multihashes are valid PeerIDs
    @Test(arguments: [HashFunction.md5, .sha1, .sha2_512, .sha3_256])
    func testUnsupportedMultihashIsRejected(function: HashFunction) throws {
        let mh = Multihash(hashing: Array("some public key".utf8), with: function)

        let error = #expect(throws: PeerID.Errors.self) { try PeerID(fromBytesID: mh.value) }
        guard case .unsupportedMultihash = error else {
            Issue.record("Expected an unsupportedMultihash error, got \(String(describing: error))")
            return
        }
        #expect(throws: PeerID.Errors.self) { try PeerID(fromHexID: mh.value.asString(base: .base16)) }
        #expect(throws: PeerID.Errors.self) {
            try PeerID(cid: CID(version: .v1, codec: .libp2p_key, multihash: mh))
        }
    }

    /// An identity multihash larger than 42 bytes is rejected (even if it contains a valid key)
    @Test func testOversizedIdentityMultihashIsRejected() throws {
        let rsa = try PeerID(.rsa(bits: .b2048))
        let inlinedRSA = try Multihash(digest: rsa.marshalPublicKey(), codec: .identity)

        #expect(throws: PeerID.Errors.invalidEmbeddedPublicKey) { try PeerID(fromBytesID: inlinedRSA.value) }

        let ecdsa = try PeerID(.ecdsa(curve: .p256))
        let inlinedECDSA = try Multihash(digest: ecdsa.marshalPublicKey(), codec: .identity)

        #expect(throws: PeerID.Errors.invalidEmbeddedPublicKey) { try PeerID(fromBytesID: inlinedECDSA.value) }
    }

    /// An identity multihash must contain a valid public key
    @Test func testIdentityMultihashWithoutAKeyIsRejected() throws {
        let garbage = try Multihash(digest: Array("not a public key".utf8), codec: .identity)
        #expect(throws: PeerID.Errors.invalidEmbeddedPublicKey) { try PeerID(fromBytesID: garbage.value) }

        let empty = try Multihash(digest: [UInt8](), codec: .identity)
        #expect(throws: PeerID.Errors.invalidEmbeddedPublicKey) { try PeerID(fromBytesID: empty.value) }
    }

    /// The inlined key must be canonically encoded, otherwise the resulting PeerID's id wouldn't match the input
    @Test func testNonCanonicalIdentityMultihashIsRejected() throws {
        let peerID = try PeerID(.secp256k1)
        let xy = try #require(peerID.keyPair?.publicKey.data)

        // A 65 byte uncompressed key (marshals to 69 bytes, too large to inline anyway)
        let uncompressed = TestFixtures.marshaledKey(type: 2, data: [0x04] + Array(xy))
        let uncompressedMH = try Multihash(digest: uncompressed, codec: .identity)
        #expect(throws: PeerID.Errors.invalidEmbeddedPublicKey) { try PeerID(fromBytesID: uncompressedMH.value) }

        // A compressed key followed by an unknown protobuf field (field 3, varint 1)
        let marshaled = try peerID.marshalPublicKey()
        let withUnknownField = marshaled + [0x18, 0x01]
        #expect(withUnknownField.count <= PeerID.maxInlineKeyLength)
        let unknownFieldMH = try Multihash(digest: withUnknownField, codec: .identity)
        #expect(throws: PeerID.Errors.invalidEmbeddedPublicKey) { try PeerID(fromBytesID: unknownFieldMH.value) }

        // While the canonical encoding is accepted
        let canonical = try PeerID(fromBytesID: Multihash(digest: marshaled, codec: .identity).value)
        #expect(canonical == peerID)
    }

    // MARK: String & CID Decoding

    /// Strings starting with `Qm` or `1` are base58btc multihashes, everything else is a multibase CIDv1
    @Test(arguments: TestFixtures.allKeyTypes)
    func testStringDecoding(keyType: LibP2PCrypto.Keys.KeyPairType) throws {
        let peerID = try PeerID(keyType)
        let cid = try CID(version: .v1, codec: .libp2p_key, multihash: peerID.multihash)

        for base in BaseEncoding.allCases {
            if base == .identity { continue }
            let encoded = try cid.toBaseEncodedString(base)
            #expect(try PeerID(cid: encoded).id == peerID.id, "Failed to decode \(base) CID \(encoded)")
        }
        #expect(try PeerID(cid: peerID.b58String).id == peerID.id)
    }

    /// v0 CIDs (implicitly dag-pb) are accepted, but v1 CIDs must use the `libp2p-key` codec
    @Test func testCIDCodecs() throws {
        let peerID = try PeerID(.ed25519)
        let traditional = Multihash(hashing: try peerID.marshalPublicKey(), with: .sha2_256)

        // CIDv0 (Qm…)
        let v0 = try CID(v0WithMultihash: traditional)
        #expect(try PeerID(cid: v0) == peerID)

        // CIDv1 dag-pb
        let v1DagPB = try CID(version: .v1, codec: .dag_pb, multihash: traditional)
        let error = #expect(throws: PeerID.Errors.self) { try PeerID(cid: v1DagPB) }
        guard case .invalidCIDCodec = error else {
            Issue.record("Expected an invalidCIDCodec error, got \(String(describing: error))")
            return
        }
        #expect(throws: PeerID.Errors.self) { try PeerID(cid: v1DagPB.toBaseEncodedString(.base32)) }

        // CIDv1 libp2p-key
        let v1 = try CID(version: .v1, codec: .libp2p_key, multihash: traditional)
        #expect(try PeerID(cid: v1) == peerID)
    }

    // MARK: Marshaled & JSON Consistency

    /// A PeerIdProto whose public key doesn't belong to its private key is rejected
    @Test func testMarshaledPublicKeyMismatchThrows() throws {
        let peerID = try PeerID(.ed25519)
        let other = try PeerID(.ed25519)

        var proto = PeerIdProto()
        proto.id = Data(peerID.id)
        proto.pubKey = Data(try other.marshalPublicKey())
        proto.privKey = Data(try peerID.marshalPrivateKey())

        #expect(throws: PeerID.MarshallingError.publicKeyMismatch) {
            try PeerID(marshaledPeerID: try proto.serializedData())
        }

        // The consistent payload is accepted
        proto.pubKey = Data(try peerID.marshalPublicKey())
        #expect(try PeerID(marshaledPeerID: try proto.serializedData()).keyPair == peerID.keyPair)
    }

    /// A JSON payload whose public key doesn't belong to its private key is rejected
    @Test func testJSONPublicKeyMismatchThrows() throws {
        let peerID = try PeerID(.secp256k1)
        let other = try PeerID(.secp256k1)

        let mismatchedPayload = PeerID.PeerIDJSON(
            id: peerID.b58String,
            pubKey: try other.marshalPublicKey().asString(base: .base64),
            privKey: try peerID.marshalPrivateKey().asString(base: .base64)
        )

        #expect(throws: PeerID.JSONError.publicKeyMismatch) {
            try PeerID(fromJSON: JSONEncoder().encode(mismatchedPayload))
        }

        let properPayload = PeerID.PeerIDJSON(
            id: peerID.b58String,
            pubKey: try peerID.marshalPublicKey().asString(base: .base64),
            privKey: try peerID.marshalPrivateKey().asString(base: .base64)
        )

        #expect(try PeerID(fromJSON: JSONEncoder().encode(properPayload)).isEquivalent(to: peerID))
    }

    /// Requesting the private key from a PeerID without one throws, rather than silently omitting it
    @Test func testToJSONWithoutPrivateKeyThrows() throws {
        let publicOnly = try PeerID(fromBytesID: PeerID(.ed25519).id)
        #expect(publicOnly.type == .isPublic)

        #expect(throws: PeerID.JSONError.noPrivateKeyAvailable) { try publicOnly.toJSON(includingPrivateKey: true) }
        #expect(throws: Never.self) { try publicOnly.toJSON() }
    }

    // MARK: RSA Key Size Limits

    /// RSA keys smaller than 2048 bits are rejected by swift-libp2p-crypto on import
    @Test func testRSA1024PublicKeyIsRejected() throws {
        let der = try TestFixtures.pemBody(PEMFixtures.RSA_1024_PUBLIC)
        let marshaled = TestFixtures.marshaledKey(type: 0, data: der)

        let error = #expect(throws: LibP2PCrypto.Keys.KeyError.self) {
            try PeerID(marshaledPublicKey: Data(marshaled))
        }
        #expect(error?.isInvalidRawRepresentation == true)
        #expect(throws: (any Error).self) { try PeerID(pem: PEMFixtures.RSA_1024_PUBLIC) }
    }

    // MARK: Equality

    @Test func testEqualityAcrossRepresentations() throws {
        let peerID = try PeerID(.ed25519)
        let traditional = Multihash(hashing: try peerID.marshalPublicKey(), with: .sha2_256)
        let traditionalPeerID = try PeerID(fromBytesID: traditional.value)

        #expect(peerID.multihash.algorithm == .identity)
        #expect(traditionalPeerID.type == .idOnly)

        // PeerID <-> PeerID
        #expect(peerID == traditionalPeerID)
        #expect(peerID.hashValue == traditionalPeerID.hashValue)

        // [UInt8] / Data <-> PeerID, in both representations
        #expect(peerID.id == traditionalPeerID)
        #expect(traditional.value == peerID)
        #expect(Data(peerID.id) == traditionalPeerID)
        #expect(Data(traditional.value) == peerID)

        // Different peers aren't equal
        let other = try PeerID(.ed25519)
        #expect(other != peerID)
        #expect((other.id == peerID) == false)
        #expect((Data(other.id) == peerID) == false)
    }

    @Test(arguments: TestFixtures.allKeyTypes)
    func testMatchesPublicKey(keyType: LibP2PCrypto.Keys.KeyPairType) throws {
        let peerID = try PeerID(keyType)
        let publicKey = try #require(peerID.keyPair?.publicKey)

        #expect(peerID.matches(publicKey: publicKey))
        #expect(try PeerID(fromBytesID: peerID.id).matches(publicKey: publicKey))
        #expect(try PeerID(.ed25519).matches(publicKey: publicKey) == false)
    }

    // MARK: Descriptions

    /// Descriptions match go-libp2p's `ShortString` (`<peer.ID xx*yyyyyy>`)
    @Test(arguments: TestFixtures.allKeyTypes)
    func testDescription(keyType: LibP2PCrypto.Keys.KeyPairType) throws {
        let peerID = try PeerID(keyType)
        let b58 = peerID.b58String

        #expect(peerID.shortDescription == "\(b58.suffix(6))")
        #expect(peerID.description == "<peer.ID \(b58.prefix(2))*\(peerID.shortDescription)>")
        #expect(peerID.toPrint() == peerID.description)
    }

    /// Secp256k1 PeerIDs share a common `16Uiu2HA` prefix, so their descriptions must still be distinct
    @Test func testSecp256k1DescriptionsAreDistinct() throws {
        let descriptions = try Set((0..<8).map { _ in try PeerID(.secp256k1).description })
        #expect(descriptions.count == 8)
    }

    /// The debug description never leaks the private key
    @Test(arguments: TestFixtures.allKeyTypes)
    func testDebugDescriptionRedactsPrivateKey(keyType: LibP2PCrypto.Keys.KeyPairType) throws {
        let peerID = try PeerID(keyType)
        let privateKey = try #require(peerID.keyPair?.privateKey)

        let debug = peerID.debugDescription
        #expect(debug.contains("<redacted>"))
        #expect(debug.contains(privateKey.asString(base: .base64Pad)) == false)
        #expect(debug.contains(try peerID.marshalPrivateKey().asString(base: .base64Pad)) == false)
        #expect(String(reflecting: peerID) == debug)
    }
}
