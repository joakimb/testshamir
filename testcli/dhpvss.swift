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
    var betas: Array<BInt>
    var vs: Array<BInt>
    var vprimes: Array<BInt>
    
}

private func deriveScrapeCoeffs(from: Int, to: Int, evaluationPoints: Array<BInt>) -> Array<BInt> {
    
    var coeffs = Array<BInt>()
    
    for i in 1...n {

        var coeff = BInt(1)
        
        for j in from...to {
            
            if (i == j){
                continue
            }
            
            let term = (evaluationPoints[i] - evaluationPoints[j]).mod(domain.order).modInverse(domain.order)
            coeff = (coeff * term).mod(domain.order)
            
        }
        
        coeffs.append(coeff)
        
    }
    
    return coeffs
    
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
    
    var betas = Array<BInt>()//(0...n)
    for i in 0...n {
        betas.append(BInt(i))
    }
    
    let vs = deriveScrapeCoeffs(from: 1, to: n, evaluationPoints: alphas)
    let vprimes = deriveScrapeCoeffs(from: 0, to: n, evaluationPoints: betas)
    
    return PVSSPubParams(t: t, n: n, alphas: alphas, betas: betas, vs: vs, vprimes: vprimes)
    
}

func dKeyGen() throws  -> (privD: BInt, pubD: Point) {
    
    let privD = randZp()
    let pubD = try toPoint(privD)
    
    return (privD,pubD)
    
}

func keyGen() throws -> (priv: BInt, pub: (E: Point, omega: DLProof)) {//skipping "id" parameter in omega
    
    let priv = randZp()
    let E = try toPoint(priv)
    let omega = try NIZKDLProve(priv)
    let pub = (E: E, omega: omega)
    
    return (priv: priv, pub: pub)
    
}

func verifyKey(E: Point, omega: DLProof) throws -> Bool {
    
    return try NIZKDLVerify(X: E, pi: omega)
    
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
    
    let coeffs = hashToPolyCoeffs(data: data, degree: pp.n - pp.t - 2)
    
    let scrapeTerms = try genScrapeSumTerms(n: pp.n, evalPoints: pp.alphas, codeCoeffs: pp.vs, polyCoeffs: coeffs)
    let V = try zip(C, scrapeTerms)
        .map{try domain.multiplyPoint($0, $1)}
        .reduce(zeroPoint){ try domain.addPoints($0,$1)}
    let U = try zip(comKeys, scrapeTerms)
        .map{try domain.multiplyPoint($0, $1)}
        .reduce(zeroPoint){ try domain.addPoints($0,$1)}
    
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
    let coeffs = hashToPolyCoeffs(data: data, degree: pp.n - pp.t - 2)
    
    let scrapeTerms = try genScrapeSumTerms(n: pp.n, evalPoints: pp.alphas, codeCoeffs: pp.vs, polyCoeffs: coeffs)
    let V = try zip(C, scrapeTerms)
        .map{try domain.multiplyPoint($0, $1)}
        .reduce(zeroPoint){ try domain.addPoints($0,$1)}
    let U = try zip(comKeys, scrapeTerms)
        .map{try domain.multiplyPoint($0, $1)}
        .reduce(zeroPoint){ try domain.addPoints($0,$1)}
    
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
func lagPubD (keys: Array<Point>, t: Int, alphas: Array<BInt>) throws -> Point {
    return try gShamirRec(shares: keys, t: t, alphas: alphas)
}

//i:th party cur epoch reshares i:th encryted shares to the next epoch committee, using ints own distkeys, pub params for next epoch and public Dist key pubD from previous epoch
func resharePVSS(
    partyIndex: Int, comPrivKey: BInt, comPubKey: Point, partyPrivD: BInt, partyPubD: Point, curEncShares: Array<Point>, prevPubD: Point, nextComKeys: Array<Point>, nextPP: PVSSPubParams ) throws -> (Array<Point>, ReshareProof) {
        
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
        
        let coeffs = hashToPolyCoeffs(data: data, degree: nextPP.n - nextPP.t - 1)
        
        //derive U, V, W (e)
        
        let encShareDiffs = try encReshares.map {
            
            try domain.subtractPoints($0, curEncShares[partyIndex])
            
        }
        
        let scrapeTerms = try genScrapeSumTerms(n: nextPP.n, evalPoints: nextPP.betas, codeCoeffs: nextPP.vprimes, polyCoeffs: coeffs)
        
        let Uprime = try zip(encShareDiffs, scrapeTerms)
            .map{try domain.multiplyPoint($0, $1)}
            .reduce(zeroPoint){ try domain.addPoints($0,$1)}
        let Vprime = try zip(nextComKeys, scrapeTerms)
            .map{try domain.multiplyPoint($0, $1)}
            .reduce(zeroPoint){ try domain.addPoints($0,$1)}
        let Wsum = scrapeTerms.reduce(BInt.ZERO){$0 + $1}
        let Wprime = try domain.multiplyPoint(prevPubD, Wsum)
        
        //prove correctness (f)
        
        let pi = try NIZKReshareProve(w1: comPrivKey, w2: partyPrivD, ga: domain.g, gb: Vprime, gc: Wprime, Y1: comPubKey, Y2: partyPubD, Y3: Uprime)
        
        return (encReshares, pi)
        
    }

func verifyReshare (partyIndex: Int, curEncShares: Array<Point>, encReshares: Array<Point>, nextComKeys: Array<Point>, nextPP: PVSSPubParams, prevPubD: Point, reshareComKey: Point, reshareDistKey: Point, pi: ReshareProof) throws -> Bool {
    
    
    //hash to poly coeffs
    
    var data = toBytes(prevPubD)
    
    for i in 0...(curEncShares.count - 1) {
        
        data = data + toBytes(curEncShares[i])
        
    }
    
    let coeffs = hashToPolyCoeffs(data: data, degree: nextPP.n - nextPP.t - 1)
    
    //derive U, V, W
    
    let encShareDiffs = try encReshares.map {
        
        try domain.subtractPoints($0, curEncShares[partyIndex])
        
    }
    
    let scrapeTerms = try genScrapeSumTerms(n: nextPP.n, evalPoints: nextPP.betas, codeCoeffs: nextPP.vprimes, polyCoeffs: coeffs)
    
    let Uprime = try zip(encShareDiffs, scrapeTerms)
        .map{try domain.multiplyPoint($0, $1)}
        .reduce(zeroPoint){ try domain.addPoints($0,$1)}
    let Vprime = try zip(nextComKeys, scrapeTerms)
        .map{try domain.multiplyPoint($0, $1)}
        .reduce(zeroPoint){ try domain.addPoints($0,$1)}
    let Wsum = scrapeTerms.reduce(BInt.ZERO){$0 + $1}
    let Wprime = try domain.multiplyPoint(prevPubD, Wsum)
    
    //verify proof (a).ii
    
    let validProof = try NIZKReshareVerify(ga: domain.g, gb: Vprime, gc: Wprime, Y1: reshareComKey, Y2: reshareDistKey, Y3: Uprime, pi: pi)
    
    return validProof
    
}

func reconstructReshare (pp: PVSSPubParams, validIndexes: Array<Int>, encReShares: Array<Point>) throws -> Point{
    
    if validIndexes.count < (pp.t + 1) {
        
        print("not enough valid reshares")
        exit(1)
        
    }
    
    let alphas = Array(validIndexes[0...t].map{BInt($0)})// first t+1 valid indexes as BInt
    
    var sum = zeroPoint
    
    for l in 0...(alphas.count - 1) {
        
        let lambda = lagX(alphas: alphas, i: l).mod(domain.order)
        let lambC = try domain.multiplyPoint(encReShares[validIndexes[l]], lambda)
        sum = try domain.addPoints(sum,lambC)
        
    }
    
    return sum
}
