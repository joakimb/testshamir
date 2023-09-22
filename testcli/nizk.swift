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
    var z: BInt
    
}

struct DLEQProof {

    var Ra: Point
    var Rb: Point
    var z: BInt
    
}

func NIZKDLProve(_ x: BInt) throws -> DLProof{

    let X = try toPoint(x)
    let r = randZp()
    let u = try toPoint(r)
    let bytes = toBytes(domain.g) + toBytes(X) + toBytes(u)
    let c = sha256(bytes).mod(domain.order)
    let z = r + c * x.mod(domain.order)
    
    return DLProof(u: u, z: z)

}

func NIZKDLVerify(X: Point, pi: DLProof) throws -> Bool {

    let bytes = toBytes(domain.g) + toBytes(X) + toBytes(pi.u)
    let c = sha256(bytes).mod(domain.order)
    
    let lhs = try toPoint(pi.z)
    var rhs = try domain.multiplyPoint(X, c)
    rhs = try domain.addPoints(pi.u, rhs)
    
    return (lhs == rhs)
    
}

func NIZKDLEQProve(exp: BInt, a: Point, A: Point, b: Point, B: Point) throws -> DLEQProof {
    
    let r = randZp()
    let Ra = try domain.multiplyPoint(a, r)
    let Rb = try domain.multiplyPoint(b, r)
    let bytes = toBytes(a) + toBytes(A) + toBytes(b) + toBytes(B) + toBytes(Ra) + toBytes(Rb)
    let c = sha256(bytes).mod(domain.order)
    let z = r - c * exp.mod(domain.order)
    
    return DLEQProof(Ra: Ra, Rb: Rb, z: z)
    
}

func NIZKDLEQVerify(a: Point, A: Point, b: Point, B: Point, pi: DLEQProof) throws -> Bool {
    
    let bytes = toBytes(a) + toBytes(A) + toBytes(b) + toBytes(B) + toBytes(pi.Ra) + toBytes(pi.Rb)
    let c = sha256(bytes).mod(domain.order)
    
    let alhs = pi.Ra
    let arhs1 = try domain.multiplyPoint(a, pi.z)
    let arhs2 = try domain.multiplyPoint(A, c)
    let arhs = try domain.addPoints(arhs1, arhs2)
    let blhs = pi.Rb
    let brhs1 = try domain.multiplyPoint(b, pi.z)
    let brhs2 = try domain.multiplyPoint(B, c)
    let brhs = try domain.addPoints(brhs1, brhs2)
    
    return ((alhs == arhs) && (blhs == brhs))

}
