//
//  dhpvss.swift
//  testcli
//
//  Created by Joakim Brorsson on 2023-09-18.
//

import Foundation
import BigInt
import SwiftECC
import CryptoSwift

struct PVSSPubParams {
    
    var t: Int
    var n: Int
    var alphas: Array<BInt>
    var vs: Array<BInt>
    
}

func setup(t: Int, n: Int) -> PVSSPubParams {
    
    guard ((n - t - 2) > 0) else {
        print("n and t relation bad")
        exit(1)
    }
    
    var alphas = Array<BInt>()//(0...n)
    for i in 0...n {
        alphas.append(BInt(i))
    }
    
    var vs = Array<BInt>()
    for i in 1...n {
        
        var v = BInt(1)
        
        for j in 1...n {
            
            if (i == j){
                continue
            }
            
            v = alphas[i] - alphas[j].mod(domain.order)
            v = v.modInverse(domain.order)
            
        }
        
        vs.append(v)
        
    }
    
    return PVSSPubParams(t: t, n: n, alphas: alphas, vs: vs)
    
}

func dKeyGen() throws  -> (privD: BInt, pubD: Point) {
    
    let privD = randZp()
    let pubD = try toPoint(privD)
    
    return (privD,pubD)
    
}

func keyGen() throws -> (priv: BInt, pub: (E: Point, omega: DLProof)) {//skipping "id" parameter in omega, seems unused
     
    let priv = randZp()
    let E = try toPoint(priv)
    let omega = try NIZKDLProve(priv)
    let pub = (E: E, omega: omega)
    return (priv: priv, pub: pub)
    
}

func verifyKey(E: Point, omega: DLProof) throws -> Bool {
    
    return try NIZKDLVerify(X: E, pi: omega)
    
}

private func hashToPolyCoeffs(data: Array<UInt8>, num: Int) -> Array<BInt> {
    
    //let the seed be the hash of the input
    //let the i:th coefficient be defined as the seed hashed i times (0 for i = 0 )
    var coeffs = Array<BInt>()
    coeffs.append(BInt(0))
    var seed = sha256(data).mod(domain.order)
    for _ in 1...(num) {
        
        coeffs.append(seed)
        seed = sha256(seed.asSignedBytes())
        
    }
            
    return coeffs
    
}

private func deriveUV(pp: PVSSPubParams, pubD: Point, C: Array<Point>, comKeys: Array<Point>) throws -> (U: Point, V: Point) {
    
    //hash to poly coeffs
    var data = toBytes(pubD)
    for i in 0...(comKeys.count - 1) {
        data = data + toBytes(comKeys[i]) + toBytes(C[i])
    }
    let coeffs = hashToPolyCoeffs(data: data, num: pp.n - pp.t - 2) // or n-t-1 ? degree or num coeffs?
    print("num coeffs m*",coeffs.count)
    
    //eval poly with hashed coeffs for V and U
    var V = try toPoint(BInt(0))
    var U = try toPoint(BInt(0))
    for x in 1...(pp.n) {
        //derive mstar
        let alpha = pp.alphas[x]
        var mstar = BInt(0)
        for i in 0...(coeffs.count-1) {
            mstar += (coeffs[i] * alpha ** i).mod(domain.order)
        }
        //add v_i * m^star(alpha_i) * C_i to V sum
        let Vterm = try domain.multiplyPoint(C[x - 1], pp.vs[x - 1] * mstar)
        V = try domain.addPoints(V, Vterm)
        //add v_i * m^star(alpha_i) * E_i to U sum
        let Uterm = try domain.multiplyPoint(comKeys[x - 1], pp.vs[x - 1] * mstar)
        U = try domain.addPoints(U, Uterm)
    }
    
    return (U,V)
}


func distributePVSS(pp: PVSSPubParams, privD: BInt, pubD: Point, comKeys: Array<Point>, S: Point) throws -> (encShares: Array<Point>, shareProof: DLEQProof){
    
    print("n:",pp.n,"t:",pp.t)
    let shares: Array<Point> = try gShamirShare(indexes: pp.alphas, S: S, t: pp.t, n: pp.n)
    
    var C = Array<Point>()
    for i in 0...(pp.n - 1){
        var c = try domain.multiplyPoint(comKeys[i], privD)
        c = try domain.addPoints(c, shares[i])
        C.append(c)
    }
    print("num C",C.count)

    let (U,V) = try deriveUV(pp: pp, pubD: pubD, C: C, comKeys: comKeys)
    
    //prove correctness
    let pi = try NIZKDLEQProve(exp: privD, a: domain.g, A: pubD, b: U, B: V)
    
    return (encShares: C, shareProof: pi)
    
}

func verifyPVSS(pp: PVSSPubParams, pubD: Point, C: Array<Point>, comKeys: Array<Point>, pi: DLEQProof) throws -> Bool {
    
    let (U,V) = try deriveUV(pp: pp, pubD: pubD, C: C, comKeys: comKeys)
    return try NIZKDLEQVerify(a: domain.g, A: pubD, b: U, B: V, pi: pi)
    
}
