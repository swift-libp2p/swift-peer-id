//
//  PeerID+Equatable.swift
//  
//
//  Created by Brandon Toms on 9/23/22.
//

import Foundation

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
