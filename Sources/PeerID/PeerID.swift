
import Foundation
import Multihash
import Multibase
import CID
import LibP2PCrypto

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
    
    /// Inits a `PeerID` from a marshaled `PeerID` string
    /// - Note: `base` can be left `nil` if the marshaledPeerID String is `Multibase` compliant (includes the multibase prefix) otherwise, you must specify the ecoded base of the string...
    public convenience init(marshaledPeerID:String, base: BaseEncoding? = nil) throws {
        let marshaledData:Data
        if let base = base {
            marshaledData = try BaseEncoding.decode(marshaledPeerID, as: base).data
        } else {
            marshaledData = try BaseEncoding.decode(marshaledPeerID).data
        }
        try self.init(marshaledPeerID: marshaledData)
    }
    
    /// Inits a `PeerID` from a marshaled `PeerID`
    public convenience init(marshaledPeerID data:Data) throws {
        // Attampt to instantiate a PeerIdProto with the raw, marshaled, data
        let protoPeerID = try PeerIdProto(contiguousBytes: data)
        
        //print(protoPeerID.id.asString(base: .base64))
        //print("Has PubKey: \(protoPeerID.hasPubKey)")
        //print(protoPeerID.pubKey.asString(base: .base64))
        //print("Has PrivKey: \(protoPeerID.hasPrivKey)")
        //print(protoPeerID.privKey.asString(base: .base64))
        
        // Enusre the Marshaled data included at least a public key (is this necessary, would we ever need to unmarshal an ID only?)
        guard protoPeerID.hasPubKey || protoPeerID.hasPrivKey else {
            throw NSError(domain: "No Public or Private Key Found in marshaled data", code: 0, userInfo: nil)
        }
        
        // If we have a private key, attempt to instantiate the PeerID via the private key, otherwise, try the public key...
        if protoPeerID.hasPrivKey {
            try self.init(marshaledPrivateKey: protoPeerID.privKey)
        } else if protoPeerID.hasPubKey {
            try self.init(marshaledPublicKey: protoPeerID.pubKey)
        } else {
            throw NSError(domain: "No Public or Private Key Found in marshaled data", code: 0, userInfo: nil)
        }
    }
    
    /// Inits a `PeerID` from a marshaled public key string
    public convenience init(marshaledPublicKey str:String, base:BaseEncoding) throws {
        try self.init(keyPair: LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: str, base: base))
    }
    
    /// Inits a `PeerID` from a marshaled public key
    public convenience init(marshaledPublicKey key:Data) throws {
        try self.init(keyPair: LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: key))
    }
    
    /// Inits a `PeerID` from a marshaled private key string
    public convenience init(marshaledPrivateKey str:String, base:BaseEncoding) throws {
        try self.init(keyPair: LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: str, base: base))
    }
    
    /// Inits a `PeerID` from a marshaled private key
    public convenience init(marshaledPrivateKey data:Data) throws {
        try self.init(keyPair: LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: data))
    }
    
    /// An Internal PeerID struct to facilitate JSON Encoding and Decoding
    internal struct PeerIDJSON:Codable {
        /// base58 encoded string
        let id:String
        /// base64 encoded publicKey protobuf
        let pubKey:String?
        /// base64 encoded privateKey protobuf
        let privKey:String?
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
    public convenience init(fromJSON json:Data) throws {
        let data = try JSONDecoder().decode(PeerIDJSON.self, from: json)
        
        if data.privKey == nil && data.pubKey == nil {
            /// Only ID Present...
            try self.init(fromBytesID: Multihash(b58String: data.id).value)
        } else if data.privKey == nil, let pubKey = data.pubKey {
            /// Only Public Key and ID Present, lets init via the public key and derive the ID
            /// TODO: Compare the provided ID and the Derived ID and throw an error if they dont match...
            try self.init(marshaledPublicKey: pubKey, base: .base64)
        } else if let privKey = data.privKey {
            /// Private Key was provided. Lets init via the private key and derive both the public key and the ID
            /// TODO: Compare the provided publicKey and ID to the ones derived from the private key and throw an error if they don't match...
            try self.init(marshaledPrivateKey: privKey, base: .base64)
        } else {
            throw NSError(domain: "Failed to init PeerID from json", code: 0, userInfo: nil)
        }
    }
    
    /// Exports our PeerID as a JSON object
    ///
    /// Returns a JSON object of the form
    /// ```
    /// {
    ///   obj.id: String - The multihash encoded in base58
    ///   obj.pubKey: String? - The public key in protobuf format, encoded in 'base64'
    ///   obj.privKey: String? - The private key in protobuf format, encoded in 'base64'
    /// }
    /// ```
    public func toJSON(includingPrivateKey:Bool = false) throws -> Data {
        let pidJSON = PeerIDJSON(
            id: self.b58String,
            pubKey: try? self.keyPair?.publicKey.marshal().asString(base: .base64),
            privKey: includingPrivateKey ? try? self.keyPair?.privateKey?.marshal().asString(base: .base64) : nil
        )
        
        return try JSONEncoder().encode(pidJSON)
    }
    
    public func toJSONString(includingPrivateKey:Bool = false) throws -> String? {
        return try String(data: self.toJSON(), encoding: .utf8)
    }
    
    
//    private static func computeDigest(pubKey:SecKey) throws -> [UInt8] {
//        let bytes = try pubKey.rawRepresentation()
//        return try self.computeDigest(rawPubKey: bytes)
//    }
//
//    /// - Note: We need to marshal the raw public key before multihashing it....
//    private static func computeDigest(rawPubKey bytes:Data) throws -> [UInt8] {
//        let marshaled = try LibP2PCrypto.Keys.marshalPublicKey(raw: bytes, keyType: .RSA(bits: .B1024))
//        //print(marshaled.asString(base: .base64Pad))
//        if marshaled.count <= 42 {
//            return try Multihash(raw: marshaled, hashedWith: .identity).value
//        } else {
//            //let mh = try Multihash(raw: bytes, hashedWith: .sha2_256)
//            //print("Value: \(mh.value.asString(base: .base16))")
//            //print("Hex: \(mh.hexString)")
//            //print("Digest: \(mh.digest?.asString(base: .base16) ?? "NIL")")
//            return try Multihash(raw: marshaled, hashedWith: .sha2_256).value //pubKey.hash()
//        }
//    }
    

    /// Returns a protocol-buffers encoded version of the id, public key and, if `includingPrivateKey` is set to `true`, the private key.
    public func marshal(includingPrivateKey:Bool = false) throws -> [UInt8] {
        var pid = PeerIdProto()
        pid.id = Data(self.id)
        pid.pubKey = try self.keyPair?.publicKey.marshal() ?? Data()
        if includingPrivateKey, let privKey = self.keyPair?.privateKey {
            pid.privKey = try privKey.marshal()
        }
        return try pid.serializedData().bytes
    }
    
    public func marshalPrivateKey() throws -> [UInt8] {
        guard let privKey = self.keyPair?.privateKey else {
            throw NSError(domain: "This PeerID doesn't have a Private Key to Marshal", code: 0, userInfo: nil)
        }
        return try privKey.marshal().bytes
    }

    public func marshalPublicKey() throws -> [UInt8] {
        guard let pubKey = self.keyPair?.publicKey else {
            throw NSError(domain: "This PeerID doesn't have a Public Key to Marshal", code: 0, userInfo: nil)
        }
        return try pubKey.marshal().bytes
    }
    
//    public func marshalPublicKeyAsProtobuf() throws -> LibP2PCrypto.PublicKey {
//        
//    }
    
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
    
    // Signs data using this PeerID's private key. This signature can then be verified by a remote peer using this PeerID's public key
    public func signature(for msg:Data) throws -> Data {
        guard let priv = keyPair?.privateKey else {
            throw NSError(domain: "A private key is required for generating signature and this PeerID doesn't contain a private key.", code: 0, userInfo: nil)
        }
        
        return try priv.sign(message: msg)
    }
    
    // Using this PeerID's public key, this method checks to see if the signature data was in fact signed by this peer and is a valid signature for the expected data
    public func isValidSignature(_ signature:Data, for expectedData:Data) throws -> Bool {
        guard let pub = keyPair?.publicKey else {
            throw NSError(domain: "A public key is required for verifying signatures and this PeerID doesn't contain a public key.", code: 0, userInfo: nil)
        }
        
        return try pub.verify(signature: signature, for: expectedData)
    }
}

extension PeerID:CustomStringConvertible {
    public var description: String {
        let pid = self.b58String
        // All sha256 nodes start with Qm
        // We can skip the Qm to make the peer.ID more useful
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
        // All sha256 nodes start with Qm
        // We can skip the Qm to make the peer.ID more useful
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

extension PeerID:Equatable {
    public static func == (lhs: PeerID, rhs: PeerID) -> Bool {
        lhs.id == rhs.id
    }
    public static func == (lhs: [UInt8], rhs: PeerID) -> Bool {
        lhs == rhs.id
    }
    public static func == (lhs: Data, rhs: PeerID) -> Bool {
        lhs.bytes == rhs.id
    }
}
//public func computeDigest(rawPubKey:Data) -> Data {
//    if rawPubKey.count <= 42 {
//        return Multihash(raw: rawPubKey, hashedWith: .identity)
//    } else {
//        return rawPubKey.hash()
//    }
//}
