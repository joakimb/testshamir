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
            v = (v * term).mod(domain.order)
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

private func scrapeSum(pp: PVSSPubParams, coeffs: Array<BInt>) throws -> BInt {
    
    //eval poly with hashed coeffs
    var sum = BInt(0)
    for x in 1...(pp.n) {
        
        //derive mstar
        let alpha = pp.alphas[x]
        var mstar = BInt(0)
        for i in 0...(coeffs.count-1) {
            mstar = (mstar + coeffs[i] * alpha ** i).mod(domain.order)
        }
        //add v_i * m^star(alpha_i) * codeWord[i] to sum
        sum = (sum + pp.vs[x - 1] * mstar).mod(domain.order)

    }
    
    return sum
    
}

private func scrapeSum(pp: PVSSPubParams, coeffs: Array<BInt>, codeWord: Array<Point>) throws -> Point {
    
    //eval poly with hashed coeffs
    var sum = try toPoint(BInt(0))
    for x in 1...(pp.n) {
        
        //derive mstar
        let alpha = pp.alphas[x]
        var mstar = BInt(0)
        for i in 0...(coeffs.count-1) {
            mstar = (mstar + coeffs[i] * alpha ** i).mod(domain.order)
        }
        //add v_i * m^star(alpha_i) * codeWord[i] to sum
        let vm = (pp.vs[x - 1] * mstar).mod(domain.order)
        let term = try domain.multiplyPoint(codeWord[x - 1], vm)
        sum = try domain.addPoints(sum, term)
        
    }
    
    return sum
    
}


func distributePVSS(pp: PVSSPubParams, privD: BInt, pubD: Point, comKeys: Array<Point>, S: Point) throws -> (encShares: Array<Point>, shareProof: DLEQProof){
    
    //secret share
    let shares = try gShamirShare(indexes: pp.alphas, S: S, t: pp.t, n: pp.n)
    
    //encrypt shares
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

//helper function to calculate pk_{D,L_{r-1}}, i.e a lagrange interpolation of the distibution keys of the t+1 parties in L for the prvious round
//which were used to reconstruct the share that is to be reshared from the current round to the next round
//this can be done by a call to shamir lagrange interpol, but with the sharares replace with the distribution keys
func lagPubD (keys: Array<Point>, t: Int, alphas: Array<BInt>) throws -> Point {
    return try gShamirRec(shares: keys, t: t, alphas: alphas)
}

//i:th party cur epoch reshares i:th encryted shares to the next epoch committee, using ints own distkeys, pub params for next epoch and public Dist key pubD from previous epoch
func resharePVSS(
    partyIndex: Int, comPrivKey: BInt, comPubKey: Point, partyPrivD: BInt, partyPubD: Point, //resharer
    curEncShares: Array<Point>, prevPubD: Point, //pubDs: Array<Point>, //comitttee data
    nextComKeys: Array<Point>, nextPP: PVSSPubParams //next comittee data
) throws -> (Array<Point>, ReshareProof) {

    // decrypt encrypted share (a)
    let decSharedKey = try domain.multiplyPoint(prevPubD,comPrivKey)
    let decShare = try domain.subtractPoints(curEncShares[partyIndex], decSharedKey)

    //create shares of it fot next epoch committe (b)
    let reShares = try gShamirShare(indexes: nextPP.alphas, S: decShare, t: nextPP.t, n: nextPP.n)

    //encrypt the shares for next epoch committee keys (c)
    var encReshares = Array<Point>()
    for i in 0...(nextPP.n - 1){
        let encSharedKey = try domain.multiplyPoint(nextComKeys[i], partyPrivD)
        let encReshare = try domain.addPoints(encSharedKey, reShares[i])
        encReshares.append(encReshare)
    }

    //hash to poly coeffs (d)
    var data = toBytes(prevPubD)
    for i in 0...(curEncShares.count - 1) {
        data = data + toBytes(curEncShares[i])
    }
    let coeffs = hashToPolyCoeffs(data: data, num: nextPP.n - nextPP.t - 1)

    //derive U, V, W (e)
    var encShareDiffs = Array<Point>()
    for i in 0...(nextPP.n - 1) {
        let encShareDiff = try domain.subtractPoints(encReshares[i], curEncShares[partyIndex])
        encShareDiffs.append(encShareDiff)
    }
    let nextU = try scrapeSum(pp: nextPP, coeffs: coeffs, codeWord: encShareDiffs)
    let nextV = try scrapeSum(pp: nextPP, coeffs: coeffs, codeWord: nextComKeys)
    let Wsum = try scrapeSum(pp: nextPP, coeffs: coeffs)
    let nextW = try domain.multiplyPoint(prevPubD, Wsum)
    
    print("Wsum",Wsum)
    print("sharing UVW", nextU, nextV, nextW)
    print("WHY ARE V AND W THE SAME")
    print("sharing Y2:", partyPubD)

    //prove correctness (f)
    let pi = try NIZKReshareProve(w1: comPrivKey, w2: partyPrivD, ga: domain.g, gb: nextV, gc: nextW, Y1: comPubKey, Y2: partyPubD, Y3: nextU)
    
    return (encReshares, pi)

}

func reconstructResharesPVSS (partyIndex: Int, curEncShares: Array<Point>, reShares: Array<Point>, nextComKeys: Array<Point>, nextPP: PVSSPubParams, prevPubD: Point, curComKey: Point, pi: ReshareProof) throws {
    
//
//    //verify proof (a).ii
//    let validProof = try NIZKReshareVerify(ga: domain.g, gb: nextV, gc: nextW, Y1: curComKey, Y2: prevPubD, Y3: nextU, pi: pi)
//    print("reshareproof",validProof)
//    print("recon UVW", nextU, nextV, nextW)
//    print("recon Y2:", prevPubD)
//
//    //TODO (b)
}
