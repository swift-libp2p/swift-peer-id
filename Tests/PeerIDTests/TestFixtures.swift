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

/// Shared fixtures and helpers for the PeerID test suites
enum TestFixtures {

    /// One of every supported key type
    static let allKeyTypes: [LibP2PCrypto.Keys.KeyPairType] = [
        .rsa(bits: .b2048),
        .ed25519,
        .secp256k1,
        .ecdsa(curve: .p256),
        .ecdsa(curve: .p384),
        .ecdsa(curve: .p521),
    ]

    /// The message used by go-libp2p's `core/crypto/test_data` signatures
    static let goMessage = Data("Libp2p is the _best_!".utf8)

    /// Decodes a (case insensitive) hex string
    static func hex(_ string: String) throws -> Data {
        Data(try BaseEncoding.decode(string.lowercased(), as: .base16))
    }

    /// Hand rolls a protobuf `PublicKey` / `PrivateKey` message (`KeyType` = field 1, `Data` = field 2)
    /// - Note: Lets us craft keys that swift-libp2p-crypto would never marshal itself (ex: uncompressed or out of range keys)
    static func marshaledKey(type: UInt8, data: [UInt8], extraBytes: [UInt8] = []) -> [UInt8] {
        [0x08, type, 0x12] + varint(data.count) + data + extraBytes
    }

    /// Minimal unsigned varint encoding
    static func varint(_ value: Int) -> [UInt8] {
        var value = UInt64(value)
        var bytes: [UInt8] = []
        repeat {
            var byte = UInt8(value & 0x7F)
            value >>= 7
            if value != 0 { byte |= 0x80 }
            bytes.append(byte)
        } while value != 0
        return bytes
    }

    /// The DER payload of a PEM string (headers / footers stripped)
    static func pemBody(_ pem: String) throws -> [UInt8] {
        let base64 = pem.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.hasPrefix("-----") }
            .joined()
        return try BaseEncoding.decode(base64, as: .base64Pad)
    }

    /// The order of the secp256k1 curve
    static let secp256k1Order: [UInt8] = Array(
        try! hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
    )
}

/// `KeyError` cases carry a detail string, these helpers let us match on the case alone
extension LibP2PCrypto.Keys.KeyError {
    var isInvalidParameters: Bool {
        if case .invalidParameters = self { return true }
        return false
    }

    var isInvalidRawRepresentation: Bool {
        if case .invalidRawRepresentation = self { return true }
        return false
    }
}

// MARK: go-libp2p Fixtures

/// Keys and signatures from go-libp2p's `core/crypto/test_data`
/// - Note: Mirrors `ECDSAFixtures` in swift-libp2p-crypto's `ECDSATests.swift`
enum GoFixtures {

    enum ECDSA {
        /// Marshaled P-256 private key (3.priv)
        static let privateKey =
            "08031279307702010104201fc05449e3a3423bb8b59447a43c3e23ad4095ac4f9fbb75457acef34b68949fa00a06082a8648ce3d030107a14403420004e29a8674f3614e0ccb72406bfe2137e9f8c5f7d62d137f0a2edd233e35374777fd1f9aed4d2cfa7371caafc6ef02db83b81f77cfe1bcd8c715acf0b9a2778ea9"

        /// Marshaled P-256 public key (3.pub)
        static let publicKey =
            "0803125b3059301306072a8648ce3d020106082a8648ce3d03010703420004e29a8674f3614e0ccb72406bfe2137e9f8c5f7d62d137f0a2edd233e35374777fd1f9aed4d2cfa7371caafc6ef02db83b81f77cfe1bcd8c715acf0b9a2778ea9"

        /// DER signature of ``TestFixtures/goMessage`` (3.sig), note: this is a high-S signature
        static let signature =
            "3046022100846a6685b9e72b560cb2fc4a75f9cbc38a90aaeaa7f3f25ee719832db7b93a65022100cd992bb7bd2bcc28c7db04987d10adc490fe348270954f7696cb0dffff0dfc3d"

        /// The PeerID derived from the key above
        static let peerID = "QmYod9tQDX9rLCrs7au5um1aDrBXTnaHGbh1W6bxNGeEut"
    }

    enum Secp256k1 {
        /// Marshaled private key
        static let privateKey = "080212203141bd606a504c44f23494d8f3174ef25b1fb9b52daa07d058be83b6e046b158"

        /// Marshaled (33 byte compressed) public key
        static let publicKey = "08021221023540ad842af8a43551a94d8383a555a99226506b88f953d2e70316a3a1b3d6a2"

        /// Deterministic (RFC 6979), low-S, DER signature of ``TestFixtures/goMessage``
        static let signature =
            "3044022031a7d633c2f3e45a16128d43751afaa8dc9ba24092c5f5b3cad2c8fe4cf388f2022049ea8d219f458683d24775d543ea8fb290704347fb35493c403bc2c259b29d9e"

        /// The (identity multihash) PeerID derived from the key above
        static let peerID = "16Uiu2HAky1YnjeGryCtGu69pvjeHXSwTHUgDNFF4zxtD5WrCPury"
    }
}

// MARK: Spec Test Vectors

/// - Reference: https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md#test-vectors
enum SpecVectors {

    enum Ed25519 {
        static let privateKey =
            "080112407e0830617c4a7de83925dfb2694556b12936c477a0e1feb2e148ec9da60fee7d1ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e"
        static let publicKey = "080112201ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e"
        static let peerID = "12D3KooWBtg3aaRMjxwedh83aGiUkwSxDwUZkzuJcfaqUmo7R3pq"
    }

    enum Secp256k1 {
        static let privateKey = "0802122053DADF1D5A164D6B4ACDB15E24AA4C5B1D3461BDBD42ABEDB0A4404D56CED8FB"
        static let publicKey = "08021221037777e994e452c21604f91de093ce415f5432f701dd8cd1a7a6fea0e630bfca99"
        static let peerID = "16Uiu2HAmLhLvBoYaoZfaMUKuibM6ac163GwKY74c5kiSLg5KvLpY"
    }
}

// MARK: PEM Fixtures

/// - Note: Copied from swift-libp2p-crypto's `Tests/LibP2PCryptoTests/Fixtures/Pem.swift`
enum PEMFixtures {

    /// An (unsupported) RSA 1024 Public Key
    static let RSA_1024_PUBLIC = """
        -----BEGIN PUBLIC KEY-----
        MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUkb0ol7/oLRbfbLqcW43xtJdh
        7xQ+Vf57DWtkEpeflZ5fUTIND+s1AlTAv63NsfUX3GJ/p+5jhnl3zweTKr7e5haM
        ZqOJaARSKpGxOBwz1K3bhvJW+izXwUrwPbcmkiAlvkAsjj1hwRpND8t/NouF+hOw
        HLQCPvkX8YLbUzoZrwIDAQAB
        -----END PUBLIC KEY-----
        """

    /// The password used to encrypt `RSA_2048_PRIVATE_ENCRYPTED`
    static let RSA_2048_PASSWORD = "mypassword"

    /// An RSA 2048 Private Key encrypted by OpenSSL
    /// (PBES2, PBKDF2-HMAC-SHA1, 2048 iterations, 8 byte salt, AES-128-CBC)
    ///
    /// Encrypted with
    /// ```
    /// openssl pkcs8
    ///     -in foo.pem
    ///     -topk8
    ///     -v2 aes-128-cbc
    ///     -passout pass:mypassword
    /// ```
    static let RSA_2048_PRIVATE_ENCRYPTED = """
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        MIIFHzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQItFN8Rv+HfeQCAggA
        MB0GCWCGSAFlAwQBAgQQSRG1ZyfCgGRU1vAqzEP8WASCBNBhmHklRhwhYxV4m0/4
        7BoZzhObOTflYi8vZ13MZlgjd/UCfp/HdeHkIuX+E2UPBz6DZaMTalHbkXJNKehI
        ZC8+1miGehBXcLg748gYytYFcGwomMsWUXs7v1EWahVxzVg6s7NwITweJ2TzlIwU
        w5QbVQHglq1difGNF0daysOrUOk1wod6U23pO9O04aYPEygqlF6aIbDTkcfEUUhr
        3GUOBtbr9Id+K4nuHT36W8gWbAmvkxa3pG0/5TcRmn7dHBRvBwyfuv37ejcYFcRR
        J4iwFaQYRrsKoYRe+IXPQosNtWGp49+mewR0cguvoIsr1EKv3UOKMg1GIu1wltkq
        ZflGYbh8j1f6l/y+92jZxpoK2XfvR0HeCZZZBnp/ooeX1qgpKMdLNssomvGRV6bd
        FXZRoC9cA9l1lYriy3ISgXG1a2DCfK2sszljZCriii51/Ba+G+/+VjOzgpYOCPsS
        LJJBQ2jFo0LE+fLEbkhcqZzrW8KMJjZPAHhO/ShV2EYMPASbOUgtJ+OWYtMJU9zK
        HjtlTe8ezH5GbUZw51ANL4tX1I9wnAMeAoUVVETBmeARZBDy2TVhZ655SXCgUJs4
        rW+jVqHRofhtEJoIjTwTFLYyDwaMXoIJUngDp4oTeNM9w28pdfX1Z/ezHX2GOV71
        mQGs7SgZ7dSsicVac8LTzH0rraf7A+GCgfMSNcsuvqIxFhk48h0w/IqT+QIOlycU
        InIMHvX6x3AoAeOwZequrKXFHp2HWLFkweM6XeebA+dl1M2E3MbsPI+Dpi7VSEW/
        F/qAfURbcqXVGv1BGnB4uPk61c/t4NdQ7jxe+6sI8nf8tMGR2lb2qZt4+qS9qw6A
        rS1wc/YmsX8jHU6lk399NCbREe//F/D4wlQjam+8lvM3klZdVm+722BC48O9hIhD
        TFDrynzeVLga+2k38gKGjkxG7vcXiuPOLUl9WZbAkMmek+S066wALRj+4r+d5U2X
        1DGoLy5drkqO+CLYbOzXS7KeEcQyu/w+oX2reFy6kpnhXnn609uv7tYodzglxD1K
        r+TfPP1w2woxV7bPEf4Ylf4pzGtD+FSk9M++swWleBGkVrwKC30eJWyQxm5A4N1U
        ZBZ+hf7HZiRvHSihm7Q2QeGyvWUc2ATxt/+J1kC2DzWEtU3UikJZ3UN5I13d5sJQ
        2/BIfleypg2U/ch/yJx6qiI5lZRbbqcPdIxREj84DtNvpTKKRL6Y3IHztu7SpEY/
        uoW2smQ74JL+bZWRXeFSoSA8CdascvMbq8ZL4tH2Hr0xyrGnf5+DbN7DcD+XUHfA
        8Vnm0jbVAtrUNrtyQ1CSIpPV7OR2VyJyuwsR0kfau1bSM405FPLoeimimSBVqJhg
        68GVHLmc6X+79RCgdbglBOaB01HRzY++DLqLwgsiaWqMUhNIHnulS7SnXu6zTViH
        jcDm0TWLVgxfDvylWcqqbybXHI7QJibkc0p+5dhi5LYChMKEXHybHwlXI0cq3QHQ
        INVmehRRj17fmoJpLWYdnnUW57mpISHKmfHHXi15YKqKlfTUAotB/6wmFhLq3XEM
        v2pHEIESHG0ZBBMKZ/zDiIkmsNpd5tcPXJ+YFweHDYWOWBMx7Lby9xKDtiayy4fq
        EBYIkwH7JeccEi7Z7+wR20+qeg==
        -----END ENCRYPTED PRIVATE KEY-----
        """
}
