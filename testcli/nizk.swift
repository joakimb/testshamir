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

struct ReshareProof {

    var R1: Point
    var R2: Point
    var R3: Point
    var z1: BInt
    var z2: BInt
    
}

func NIZKDLProve(_ x: BInt) throws -> DLProof{

    let X = try toPoint(x)
    let r = randZp()
    let u = try toPoint(r)
    let bytes = toBytes(domain.g) + toBytes(X) + toBytes(u)
    let c = sha256(bytes).mod(domain.order)
    let z = (r + c * x).mod(domain.order)
    
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
    let z = (r - c * exp).mod(domain.order)
    
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

//prove knowledge of w_1 and w_2 so that Y_1 = g_a^w_1 && Y_2 = g_a^w_2 && Y_3 = (g_b^w_2 * g_c ^ -w_1), note that Y3 is a pdersen commitment
func NIZKReshareProve(w1: BInt, w2: BInt, ga: Point, gb: Point, gc: Point, Y1: Point, Y2: Point, Y3: Point) throws -> ReshareProof {
    
    let r1 = randZp()
    let r2 = randZp()
    let R1 = try domain.multiplyPoint(ga, r1)
    let R2 = try domain.multiplyPoint(ga, r2)
    let gbr2 = try domain.multiplyPoint(gb, r2)
    let gcr1 = try domain.multiplyPoint(gc, r1)
    let R3 = try domain.subtractPoints(gbr2, gcr1)
    
    let bytes = toBytes(ga) + toBytes(gb) + toBytes(gc) + toBytes(Y1) + toBytes(Y2) + toBytes(Y3) + toBytes(R1) + toBytes(R2) + toBytes(R3)
    let c = sha256(bytes).mod(domain.order)
    
    let z1 = (r1 + c * w1).mod(domain.order)
    let z2 = (r2 + c * w2).mod(domain.order)
    
    return ReshareProof(R1: R1, R2: R2, R3: R3, z1: z1, z2: z2)

}

func NIZKReshareVerify(ga: Point, gb: Point, gc: Point, Y1: Point, Y2: Point, Y3: Point, pi: ReshareProof) throws -> Bool {
    
    let bytes = toBytes(ga) + toBytes(gb) + toBytes(gc) + toBytes(Y1) + toBytes(Y2) + toBytes(Y3) + toBytes(pi.R1) + toBytes(pi.R2) + toBytes(pi.R3)
    let c = sha256(bytes).mod(domain.order)
    
    //check dl for Y1
    let cY1 = try domain.multiplyPoint(Y1, c)
    let R1cY1 = try domain.addPoints(pi.R1, cY1)
    let z1ga = try domain.multiplyPoint(ga, pi.z1)
    let DLcheck1 = (R1cY1 == z1ga)
    
    //check dl for Y2
    let cY2 = try domain.multiplyPoint(Y2, c)
    let R2cY2 = try domain.addPoints(pi.R2, cY2)
    let z2ga = try domain.multiplyPoint(ga, pi.z2)
    let DLcheck2 = (R2cY2 == z2ga)
    
    //check pedersen commitment for Y3
    let cY3 = try domain.multiplyPoint(Y3, c)
    let R3cY3 = try domain.addPoints(pi.R3, cY3)
    let z2gb = try domain.multiplyPoint(gb, pi.z2)
    let z1gc = try domain.multiplyPoint(gc, pi.z1)
    let z2gb_z1gc = try domain.subtractPoints(z2gb, z1gc)
    let pedersencheck = (R3cY3 == z2gb_z1gc)
    
    return (DLcheck1 && DLcheck2 && pedersencheck)
    
}
