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

struct DLEQProof {

    var Ra: Point
    var Rb: Point
    var c: BInt
    var z: BInt
    
}

func NIZKDLProve(_ x: BInt) throws -> DLProof{

    let X = try toPoint(x)
    let r = randZp()
    let u = try toPoint(r)
    let bytes = toBytes(domain.g) + toBytes(X) + toBytes(u)
    let c = sha256(bytes) % domain.order
    let z = r + c * x % domain.order
    
    return DLProof(u: u, c: c, z: z)

}

func NIZKDLVerify(X: Point, pi: DLProof) throws -> Bool {

    let bytes = toBytes(domain.g) + toBytes(X) + toBytes(pi.u)
    let cprime = sha256(bytes) % domain.order
    let fsCheck = (pi.c == cprime)
    
    let lhs = try toPoint(pi.z)
    var rhs = try domain.multiplyPoint(X, pi.c)
    rhs = try domain.addPoints(pi.u, rhs)
    let schnorrCheck = (lhs == rhs)
    
    return (fsCheck && schnorrCheck)
    
}

func NIZKDLEQProve(exp: BInt, a: Point, A: Point, b: Point, B: Point) throws -> DLEQProof {
    
    let r = randZp()
    let Ra = try domain.multiplyPoint(a, r)
    let Rb = try domain.multiplyPoint(b, r)
    let bytes = toBytes(a) + toBytes(A) + toBytes(b) + toBytes(B) + toBytes(Ra) + toBytes(Rb)
    let c = sha256(bytes) % domain.order
    let z = r - c * exp % domain.order
    
    return DLEQProof(Ra: Ra, Rb: Rb, c: c, z: z)
    
}

func NIZKDLEQVerify(a: Point, A: Point, b: Point, B: Point, pi: DLEQProof) throws -> Bool {
    
    let bytes = toBytes(a) + toBytes(A) + toBytes(b) + toBytes(B) + toBytes(pi.Ra) + toBytes(pi.Rb)
    let cprime = sha256(bytes) % domain.order
    let fsCheck = (pi.c == cprime)
    
    let alhs = pi.Ra
    let arhs1 = try domain.multiplyPoint(a, pi.z)
    let arhs2 = try domain.multiplyPoint(A, pi.c)
    let arhs = try domain.addPoints(arhs1, arhs2)
    let blhs = pi.Rb
    let brhs1 = try domain.multiplyPoint(b, pi.z)
    let brhs2 = try domain.multiplyPoint(B, pi.c)
    let brhs = try domain.addPoints(brhs1, brhs2)
    let chaumPedersenCheckA = (alhs == arhs)
    let chaumPedersenCheckB = (blhs == brhs)
    
    return (fsCheck && chaumPedersenCheckA && chaumPedersenCheckB)

}
