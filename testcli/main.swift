//
//  main.swift
//  testcli
//
//  Created by Joakim Brorsson on 2023-08-30.
//
import SwiftECC
import Foundation
import BigInt

////test ECC shamir
print("SSS+++++++++++++++++++++++++++++++++")
let t = 2// t+1 needed to reconstruct
let n = 5

let S = try toPoint(BInt(34))
print("secret", S)
let pp = setup(t: t,n: n)
let alphas = pp.alphas
let shares = try gShamirShare(indexes: alphas, S: S, t: t, n: n)
let ssreconstruct = (alphas: Array(alphas[2...t+2]), shares: Array(shares[1...t+1]))
print("recreated",try gShamirRec(shares: ssreconstruct.shares, t: t, alphas: ssreconstruct.alphas))

//test schnorr fiat-shamir
print("SCHNORR FS+++++++++++++++++++++++++++++++++")
let x = BInt(5)
let X = try toPoint(x)
let y = BInt(6)
let Y = try toPoint(y)
let pi = try NIZKDLProve(x)
print(pi)
let valid = try NIZKDLVerify(X: X, pi: pi)
print("true dl nizk:",valid)
let invalid = try NIZKDLVerify(X: Y, pi: pi)
print("false dl nizk:",invalid)

//test chaum-pedersen fiat-shamir
print("CHAUM-PEDERSEN FS+++++++++++++++++++++++++++++++++")
let exp = BInt(5)
let a = try toPoint(randZp())
let b = try toPoint(randZp())
let A = try domain.multiplyPoint(a, exp)
let B = try domain.multiplyPoint(b, exp)
let Bad = try domain.multiplyPoint(b, BInt(6))
let pieq = try NIZKDLEQProve(exp: exp, a: a, A: A, b: b, B: B)
let valideq = try NIZKDLEQVerify(a: a, A: A, b: b, B: B, pi: pieq)
print("true dleq nizk:",valideq)
let invalideq = try NIZKDLEQVerify(a: a, A: A, b: b, B: Bad, pi: pieq)
print("false dleq nizk:",invalideq)

//test resharenizk
print("RESHARE NIZK FS+++++++++++++++++++++++++++++++++")
let w1 = BInt(5)
let w2 = BInt(7)
let ga = try toPoint(randZp())
let gb = try toPoint(randZp())
let gc = try toPoint(randZp())
let Y1 = try domain.multiplyPoint(ga, w1)
let Y2 = try domain.multiplyPoint(ga, w2)
let w2gb = try domain.multiplyPoint(gb, w2)
let w1gc = try domain.multiplyPoint(gc, w1)
let Y3 = try domain.subtractPoints(w2gb, w1gc)
let pireshare = try NIZKReshareProve(w1: w1, w2: w2, ga: ga, gb: gb, gc: gc, Y1: Y1, Y2: Y2, Y3: Y3)
let validreshare = try NIZKReshareVerify(ga: ga, gb: gb, gc: gc, Y1: Y1, Y2: Y2, Y3: Y3, pi: pireshare)
let invalidreshare1 = try NIZKReshareVerify(ga: ga, gb: gb, gc: gc, Y1: Bad, Y2: Y2, Y3: Y3, pi: pireshare)
let invalidreshare2 = try NIZKReshareVerify(ga: ga, gb: gb, gc: gc, Y1: Y1, Y2: Bad, Y3: Y3, pi: pireshare)
let invalidreshare3 = try NIZKReshareVerify(ga: ga, gb: gb, gc: gc, Y1: Y1, Y2: Y2, Y3: Bad, pi: pireshare)
print("true reshare nizk:",validreshare)
print("false1 reshare nizk:",invalidreshare1)
print("false2 reshare nizk:",invalidreshare2)
print("false3 reshare nizk:",invalidreshare3)

//test DHPVSS
print("PVSS+++++++++++++++++++++++++++++++++")
let (privD,pubD) = try dKeyGen()
var comPubKeys = Array<Point>()
var comPrivKeys = Array<BInt>()
for _ in 1...n {
    let (privKey, pubKey) = try keyGen()
    comPubKeys.append(pubKey.E)
    comPrivKeys.append(privKey)
}
let (encShares, piPvss) = try distributePVSS(pp: pp, privD: privD, pubD: pubD, comKeys: comPubKeys, S: S)

let validpvss = try verifyPVSS(pp: pp, pubD: pubD, C: encShares, comKeys: comPubKeys, pi: piPvss)
print("true pvss:",validpvss)
let invalidpvss = try verifyPVSS(pp: pp, pubD: S, C: encShares, comKeys: comPubKeys, pi: piPvss)
print("false pvss:",invalidpvss)

//decrypt
var decShares = Array<Point>()
for i in 0...(n-1) {
    let (dShare, pi) = try decPVSSShare(pubD: pubD, privC: comPrivKeys[i], pubC: comPubKeys[i], eShare: encShares[i])
    let goodShare = try verifyDecPVSSShare(pubD: pubD, pubC: comPubKeys[i], eShare: encShares[i], dShare: dShare, pi: pi)
    if (!goodShare) {
        print("BAD SHARE")
    } else {
        decShares.append(dShare)
        print("GOOD SHARE")
    }
}
//reconstruct secret
let reconstructedSecret = try recPVSS(shares: Array(decShares[1...t+1]) , t: pp.t, alphas: Array(pp.alphas[2...t+2]))
print("shared:", S, "recon:", reconstructedSecret)

//reshare with pubD from original distributor

// how to bootstrap th pk_D



//var comPubKeys = Array<Point>()
//var comPrivKeys = Array<BInt>()
//for _ in 1...n {
//    let (privKey, pubKey) = try keyGen()
//    comPubKeys.append(pubKey.E)
//    comPrivKeys.append(privKey)
//}


//TODO: make a second reshare with pubD derived from prev com pubD keys
////construct pk_{D,L_{r-1}}
//var reconKeys = Array<Point>()
//for i in curReconstructIndexes {
//
//    guard let index = i.asInt() else {
//        print("alpha too long")
//        exit(1)
//    }
//    reconKeys.append(pubDs[index])
//
//}
//let lagPubD = try lagPubD(keys: reconKeys, t: t, alphas:curReconstructIndexes)
