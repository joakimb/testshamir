//
//  nizk.swift
//  testcli
//
//  Created by Joakim Brorsson on 2023-09-19.
//

import Foundation
import BigInt
import SwiftECC
//fiat shamir schnorr from:
//https://crypto.stanford.edu/cs355/19sp/lec5.pdf

struct DLProof {

    var u: Point
    var c: BInt
    var z: BInt
    
}

func NIZKDLProve(_ x: BInt) throws -> DLProof{

    let X = try toPoint(x)
    let r = randZp()
    let u = try toPoint(r)
    let bytes = toBytes(domain.g) + toBytes(X) + toBytes(u)
    let c = sha256(bytes)
    let z = r + c * x
    
    return DLProof(u: u, c: c, z: z)

}

func NIZKDLVerify(X: Point, pi: DLProof) throws -> Bool {

    let bytes = toBytes(domain.g) + toBytes(X) + toBytes(pi.u)
    let cprime = sha256(bytes)
    let fsCheck = (pi.c == cprime)
    
    let lhs = try toPoint(pi.z)
    var rhs = try domain.multiplyPoint(X, pi.c)
    rhs = try domain.addPoints(pi.u, rhs)
    let schnorrCheck = (lhs == rhs)
    
    return (fsCheck && schnorrCheck)
    

}
