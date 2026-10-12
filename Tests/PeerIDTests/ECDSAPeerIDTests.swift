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

/// Tests ECDSA (P-256 / P-384 / P-521) behavior
///
/// - Keys are marshaled as PKIX (public) / SEC1 (private) DER
/// - Signatures are SHA-256 + DER for every curve, and high-S signatures are accepted (matching go-libp2p)
/// - Marshaled ECDSA public keys are larger than 42 bytes, so the PeerID is a SHA-256 multihash (`Qm…`)
@Suite("ECDSA PeerID Tests")
struct ECDSAPeerIDTests {

    @Test(arguments: LibP2PCrypto.Keys.EllipticCurve.allCases)
    func testGenerate(curve: LibP2PCrypto.Keys.EllipticCurve) throws {
        let peerID = try PeerID(.ecdsa(curve: curve))

        #expect(peerID.type == .isPrivate)
        #expect(peerID.keyPair?.keyType == .ecdsa)
        #expect(peerID.keyPair?.attributes()?.size == curve.bits)

        // ECDSA keys are too large to inline
        #expect(peerID.multihash.algorithm == .sha2_256)
        #expect(peerID.b58String.hasPrefix("Qm"))
        #expect(try peerID.marshalPublicKey().count > PeerID.maxInlineKeyLength)

        // So they can't be recovered from the id alone
        let recovered = try PeerID(fromBytesID: peerID.id)
        #expect(recovered.type == .idOnly)
        #expect(recovered == peerID)
    }

    @Test(arguments: LibP2PCrypto.Keys.EllipticCurve.allCases)
    func testSignAndVerify(curve: LibP2PCrypto.Keys.EllipticCurve) throws {
        let peerID = try PeerID(.ecdsa(curve: curve))
        let message = Data("Hello ECDSA \(curve)".utf8)

        let signature = try peerID.signature(for: message)
        // DER encoded `SEQUENCE { r, s }`
        #expect(signature.first == 0x30)
        #expect(try peerID.isValidSignature(signature, for: message))

        // A public only PeerID can verify, but not sign
        let publicOnly = try PeerID(marshaledPublicKey: Data(try peerID.marshalPublicKey()))
        #expect(publicOnly.type == .isPublic)
        #expect(try publicOnly.isValidSignature(signature, for: message))
        #expect(throws: PeerID.SignatureError.noPrivateKeyAvailable) {
            try publicOnly.signature(for: message)
        }

        // A tampered message is rejected (without throwing)
        #expect(try peerID.isValidSignature(signature, for: Data("Tampered".utf8)) == false)

        // A signature from another key is rejected (without throwing)
        let other = try PeerID(.ecdsa(curve: curve))
        #expect(try other.isValidSignature(signature, for: message) == false)

        // Malformed (non DER) signatures throw
        let error = #expect(throws: LibP2PCrypto.Keys.KeyError.self) {
            try peerID.isValidSignature(Data(repeating: 0x01, count: 64), for: message)
        }
        #expect(error?.isInvalidParameters == true)
    }

    @Test(arguments: LibP2PCrypto.Keys.EllipticCurve.allCases)
    func testMarshalRoundTrip(curve: LibP2PCrypto.Keys.EllipticCurve) throws {
        let peerID = try PeerID(.ecdsa(curve: curve))

        let full = try PeerID(marshaledPeerID: Data(try peerID.marshal(includingPrivateKey: true)))
        #expect(full.type == .isPrivate)
        #expect(full.keyPair == peerID.keyPair)

        let publicOnly = try PeerID(marshaledPeerID: Data(try peerID.marshal()))
        #expect(publicOnly.type == .isPublic)
        #expect(publicOnly.id == peerID.id)

        let fromPrivateKey = try PeerID(marshaledPrivateKey: Data(try peerID.marshalPrivateKey()))
        #expect(fromPrivateKey.keyPair == peerID.keyPair)
    }

    @Test(arguments: LibP2PCrypto.Keys.EllipticCurve.allCases)
    func testJSONRoundTrip(curve: LibP2PCrypto.Keys.EllipticCurve) throws {
        let peerID = try PeerID(.ecdsa(curve: curve))

        let full = try PeerID(fromJSON: peerID.toJSON(includingPrivateKey: true))
        #expect(full.type == .isPrivate)
        #expect(full.keyPair == peerID.keyPair)

        let publicOnly = try PeerID(fromJSON: peerID.toJSON())
        #expect(publicOnly.type == .isPublic)
        #expect(publicOnly.id == peerID.id)
    }

    // MARK: go-libp2p Interop

    /// go-libp2p's P-256 key derives the same PeerID, and re-marshals byte for byte (deterministic encoding)
    @Test func testGoFixtureKeys() throws {
        let fromPrivate = try PeerID(marshaledPrivateKey: TestFixtures.hex(GoFixtures.ECDSA.privateKey))
        let fromPublic = try PeerID(marshaledPublicKey: TestFixtures.hex(GoFixtures.ECDSA.publicKey))

        #expect(fromPrivate.b58String == GoFixtures.ECDSA.peerID)
        #expect(fromPublic.b58String == GoFixtures.ECDSA.peerID)
        #expect(fromPrivate.keyPair?.attributes()?.size == 256)

        #expect(try fromPrivate.marshalPrivateKey().asString(base: .base16) == GoFixtures.ECDSA.privateKey)
        #expect(try fromPrivate.marshalPublicKey().asString(base: .base16) == GoFixtures.ECDSA.publicKey)
        #expect(try fromPublic.marshalPublicKey().asString(base: .base16) == GoFixtures.ECDSA.publicKey)

        // The string forms parse back into the same peer
        #expect(try PeerID(cid: GoFixtures.ECDSA.peerID) == fromPublic)
        #expect(try PeerID(cid: fromPublic.cidString) == fromPublic)
    }

    /// go-libp2p's (high-S) signature verifies
    @Test func testGoFixtureSignatureVerifies() throws {
        let peerID = try PeerID(marshaledPublicKey: TestFixtures.hex(GoFixtures.ECDSA.publicKey))
        let signature = try TestFixtures.hex(GoFixtures.ECDSA.signature)

        #expect(try peerID.isValidSignature(signature, for: TestFixtures.goMessage))
        #expect(try peerID.isValidSignature(signature, for: Data("Libp2p is the _worst_!".utf8)) == false)
    }

    /// Signatures we produce with go-libp2p's key verify against go-libp2p's public key
    @Test func testSignWithGoFixtureKey() throws {
        let signer = try PeerID(marshaledPrivateKey: TestFixtures.hex(GoFixtures.ECDSA.privateKey))
        let verifier = try PeerID(marshaledPublicKey: TestFixtures.hex(GoFixtures.ECDSA.publicKey))

        let signature = try signer.signature(for: TestFixtures.goMessage)
        #expect(try verifier.isValidSignature(signature, for: TestFixtures.goMessage))
    }
}
