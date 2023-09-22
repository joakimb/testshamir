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
            
            let term = (alphas[i] - alphas[j]).mod(domain.order)
            v = v * term.modInverse(domain.order)
            
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

private func scrapeSum(pp: PVSSPubParams, coeffs: Array<BInt>, codeWord: Array<Point>) throws -> Point {
    
    //eval poly with hashed coeffs
    var sum = try toPoint(BInt(0))
    for x in 1...(pp.n) {
        
        //derive mstar
        let alpha = pp.alphas[x]
        var mstar = BInt(0)
        for i in 0...(coeffs.count-1) {
            mstar += (coeffs[i] * alpha ** i).mod(domain.order)
        }
        //add v_i * m^star(alpha_i) * codeWord[i] to sum
        let term = try domain.multiplyPoint(codeWord[x - 1], pp.vs[x - 1] * mstar)
        sum = try domain.addPoints(sum, term)
        
    }
    
    return sum
    
}


func distributePVSS(pp: PVSSPubParams, privD: BInt, pubD: Point, comKeys: Array<Point>, S: Point) throws -> (encShares: Array<Point>, shareProof: DLEQProof){
    
    let shares: Array<Point> = try gShamirShare(indexes: pp.alphas, S: S, t: pp.t, n: pp.n)
    
    var C = Array<Point>()
    for i in 0...(pp.n - 1){
        var c = try domain.multiplyPoint(comKeys[i], privD)
        c = try domain.addPoints(c, shares[i])
        C.append(c)
    }
    
    //hash to poly coeffs
    var data = toBytes(pubD)
    for i in 0...(comKeys.count - 1) {
        data = data + toBytes(comKeys[i]) + toBytes(C[i])
    }
    let coeffs = hashToPolyCoeffs(data: data, num: pp.n - pp.t - 2)

    //this evaluates the same polynomial twice, can be made more efficient
    let U = try scrapeSum(pp: pp, coeffs: coeffs, codeWord: C)
    let V = try scrapeSum(pp: pp, coeffs: coeffs, codeWord: comKeys)
    
    //prove correctness
    let pi = try NIZKDLEQProve(exp: privD, a: domain.g, A: pubD, b: U, B: V)

    return (encShares: C, shareProof: pi)
    
}

func verifyPVSS(pp: PVSSPubParams, pubD: Point, C: Array<Point>, comKeys: Array<Point>, pi: DLEQProof) throws -> Bool {
    
    //hash to poly coeffs
    var data = toBytes(pubD)
    for i in 0...(comKeys.count - 1) {
        data = data + toBytes(comKeys[i]) + toBytes(C[i])
    }
    let coeffs = hashToPolyCoeffs(data: data, num: pp.n - pp.t - 2)
    
    let U = try scrapeSum(pp: pp, coeffs: coeffs, codeWord: C)
    let V = try scrapeSum(pp: pp, coeffs: coeffs, codeWord: comKeys)
    
    return try NIZKDLEQVerify(a: domain.g, A: pubD, b: U, B: V, pi: pi)
    
}

func decPVSSShare(pubD: Point, privC: BInt, pubC: Point, eShare: Point ) throws -> (share: Point, pi: DLEQProof) {
    
    let sharedKey = try domain.multiplyPoint(pubD,privC)
    let dShare = try domain.subtractPoints(eShare, sharedKey)
    let diff = try domain.subtractPoints(eShare, dShare)
    let pi = try NIZKDLEQProve(exp: privC, a: domain.g, A: pubC, b: pubD, B: diff)
    
    return(dShare, pi)
    
}

func verifyDecPVSSShare(pubD: Point, pubC: Point, eShare: Point, dShare: Point, pi: DLEQProof) throws -> Bool {
    
    let diff = try domain.subtractPoints(eShare, dShare)
    return try NIZKDLEQVerify(a: domain.g, A: pubC, b: pubD, B: diff, pi: pi)
    
}

func recPVSS(shares: Array<Point>, t: Int, alphas: Array<BInt>) throws -> Point {
    
    return try gShamirRec(shares: shares, t: t, alphas: alphas)
    
}

func resharePVSS() {
    
}
