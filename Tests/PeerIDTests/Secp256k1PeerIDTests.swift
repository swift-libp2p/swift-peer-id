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

import Foundation
import LibP2PCrypto
import Multibase
import Multicodec
import Multihash
import Testing

@testable import PeerID

/// Tests the Secp256k1 key behavior
///
/// - Signatures are SHA-256 + ECDSA, deterministic (RFC 6979), low-S and DER encoded (matching go-libp2p / rust-libp2p)
/// - Verification rejects high-S signatures (returns `false`) and throws on non DER (ex: 64 byte compact) signatures
/// - Public keys are always marshaled in their 33 byte compressed form, so the PeerID is an identity multihash (`16Uiu2HA…`)
@Suite("Secp256k1 PeerID Tests")
struct Secp256k1PeerIDTests {

    // MARK: go-libp2p Interop

    @Test func testGoFixtureKeys() throws {
        let fromPrivate = try PeerID(marshaledPrivateKey: TestFixtures.hex(GoFixtures.Secp256k1.privateKey))
        let fromPublic = try PeerID(marshaledPublicKey: TestFixtures.hex(GoFixtures.Secp256k1.publicKey))

        // The derived public key matches go's
        #expect(try fromPrivate.marshalPublicKey().asString(base: .base16) == GoFixtures.Secp256k1.publicKey)
        #expect(try fromPrivate.marshalPrivateKey().asString(base: .base16) == GoFixtures.Secp256k1.privateKey)

        // The key is inlined using the identity multihash
        #expect(fromPrivate.multihash.algorithm == .identity)
        #expect(fromPrivate.b58String == GoFixtures.Secp256k1.peerID)
        #expect(fromPublic.b58String == GoFixtures.Secp256k1.peerID)
        #expect(fromPrivate.b58String.hasPrefix("16Uiu2HA"))

        // So the public key can be recovered from the id alone
        let recovered = try PeerID(cid: GoFixtures.Secp256k1.peerID)
        #expect(recovered.type == .isPublic)
        #expect(try recovered.marshalPublicKey().asString(base: .base16) == GoFixtures.Secp256k1.publicKey)
    }

    /// Signing is deterministic (RFC 6979), so we must produce go-libp2p's signature byte for byte
    @Test func testGoFixtureSignatureIsReproduced() throws {
        let peerID = try PeerID(marshaledPrivateKey: TestFixtures.hex(GoFixtures.Secp256k1.privateKey))

        let signature = try peerID.signature(for: TestFixtures.goMessage)
        #expect(signature.asString(base: .base16) == GoFixtures.Secp256k1.signature)

        // And go's signature verifies against the public key recovered from the PeerID
        let recovered = try PeerID(cid: GoFixtures.Secp256k1.peerID)
        let goSignature = try TestFixtures.hex(GoFixtures.Secp256k1.signature)
        #expect(try recovered.isValidSignature(goSignature, for: TestFixtures.goMessage))
        #expect(try recovered.isValidSignature(goSignature, for: Data("Libp2p is the _worst_!".utf8)) == false)
    }

    // MARK: Spec Test Vectors

    @Test func testSpecVector() throws {
        let peerID = try PeerID(marshaledPrivateKey: TestFixtures.hex(SpecVectors.Secp256k1.privateKey))
        #expect(try peerID.marshalPublicKey().asString(base: .base16) == SpecVectors.Secp256k1.publicKey)
        #expect(peerID.b58String == SpecVectors.Secp256k1.peerID)
        #expect(try PeerID(cid: SpecVectors.Secp256k1.peerID) == peerID)
    }

    // MARK: Signatures

    @Test func testSignaturesAreDERAndLowS() throws {
        let peerID = try PeerID(.secp256k1)

        for i in 0..<16 {
            let message = Data("message \(i)".utf8)
            let signature = try peerID.signature(for: message)

            #expect(signature.first == 0x30)
            let (_, s) = try Secp256k1PeerIDTests.derComponents(Array(signature))
            let highS = Secp256k1PeerIDTests.subtract(TestFixtures.secp256k1Order, Secp256k1PeerIDTests.pad32(s))
            // Low-S means `s <= n - s` (both as 32 byte big endian integers)
            #expect(Secp256k1PeerIDTests.pad32(s).lexicographicallyPrecedes(highS))

            #expect(try peerID.isValidSignature(signature, for: message))
            // Signatures are deterministic
            #expect(try peerID.signature(for: message) == signature)
        }
    }

    /// The malleated (high-S) form of a valid signature is rejected
    @Test func testHighSSignatureIsRejected() throws {
        let peerID = try PeerID(.secp256k1)
        let message = Data("malleable".utf8)
        let signature = try peerID.signature(for: message)

        let (r, s) = try Secp256k1PeerIDTests.derComponents(Array(signature))
        let highS = Secp256k1PeerIDTests.subtract(TestFixtures.secp256k1Order, Secp256k1PeerIDTests.pad32(s))
        let malleated = Data(Secp256k1PeerIDTests.derEncode(r: r, s: highS))
        #expect(malleated != signature)

        #expect(try peerID.isValidSignature(malleated, for: message) == false)
    }

    /// Only DER encoded signatures are supported, compact (64 byte r || s) signatures throw
    @Test func testCompactSignatureThrows() throws {
        let peerID = try PeerID(.secp256k1)
        let message = Data("compact".utf8)
        let (r, s) = try Secp256k1PeerIDTests.derComponents(Array(try peerID.signature(for: message)))
        let compact = Data(Secp256k1PeerIDTests.pad32(r) + Secp256k1PeerIDTests.pad32(s))

        let error = #expect(throws: LibP2PCrypto.Keys.KeyError.self) {
            try peerID.isValidSignature(compact, for: message)
        }
        #expect(error?.isInvalidParameters == true)
    }

    @Test func testSignAndVerify() throws {
        let peerID = try PeerID(.secp256k1)
        let message = Data("Hello Secp256k1".utf8)
        let signature = try peerID.signature(for: message)

        let publicOnly = try PeerID(fromBytesID: peerID.id)
        #expect(publicOnly.type == .isPublic)
        #expect(try publicOnly.isValidSignature(signature, for: message))
        #expect(try publicOnly.isValidSignature(signature, for: Data("Tampered".utf8)) == false)
        #expect(throws: PeerID.SignatureError.noPrivateKeyAvailable) {
            try publicOnly.signature(for: message)
        }

        let other = try PeerID(.secp256k1)
        #expect(try other.isValidSignature(signature, for: message) == false)
    }

    // MARK: Public Key Encodings

    /// Uncompressed (65 byte) and raw (64 byte) public keys are accepted and normalized to the compressed (33 byte) form
    @Test(arguments: [true, false])
    func testUncompressedPublicKeysAreNormalized(includePrefix: Bool) throws {
        let peerID = try PeerID(.secp256k1)
        let xy = try #require(peerID.keyPair?.publicKey.data)
        #expect(xy.count == 64)

        let raw = (includePrefix ? [0x04] : []) + Array(xy)
        let marshaled = TestFixtures.marshaledKey(type: 2, data: raw)

        let normalized = try PeerID(marshaledPublicKey: Data(marshaled))
        #expect(normalized.id == peerID.id)
        #expect(try normalized.marshalPublicKey() == peerID.marshalPublicKey())
        #expect(try normalized.marshalPublicKey().count == 37)
    }

    // MARK: Helpers

    /// Splits a DER `SEQUENCE { INTEGER r, INTEGER s }` into its (minimal, unsigned) components
    static func derComponents(_ der: [UInt8]) throws -> (r: [UInt8], s: [UInt8]) {
        try #require(der.count > 8 && der[0] == 0x30 && der[2] == 0x02)
        let rLength = Int(der[3])
        let r = Array(der[4..<(4 + rLength)])
        try #require(der[4 + rLength] == 0x02)
        let sLength = Int(der[5 + rLength])
        let s = Array(der[(6 + rLength)..<(6 + rLength + sLength)])
        return (stripLeadingZeros(r), stripLeadingZeros(s))
    }

    /// Encodes `r` and `s` as a DER `SEQUENCE { INTEGER r, INTEGER s }`
    static func derEncode(r: [UInt8], s: [UInt8]) -> [UInt8] {
        func integer(_ bytes: [UInt8]) -> [UInt8] {
            var value = stripLeadingZeros(bytes)
            if let first = value.first, first & 0x80 != 0 { value.insert(0x00, at: 0) }
            return [0x02, UInt8(value.count)] + value
        }
        let body = integer(r) + integer(s)
        return [0x30, UInt8(body.count)] + body
    }

    static func stripLeadingZeros(_ bytes: [UInt8]) -> [UInt8] {
        Array(bytes.drop(while: { $0 == 0 }))
    }

    static func pad32(_ bytes: [UInt8]) -> [UInt8] {
        let stripped = stripLeadingZeros(bytes)
        return [UInt8](repeating: 0, count: max(0, 32 - stripped.count)) + stripped
    }

    /// `a - b` for 32 byte big endian unsigned integers (assumes `a >= b`)
    static func subtract(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for i in stride(from: 31, through: 0, by: -1) {
            var diff = Int(a[i]) - Int(b[i]) - borrow
            borrow = diff < 0 ? 1 : 0
            if diff < 0 { diff += 256 }
            result[i] = UInt8(diff)
        }
        return result
    }
}
