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
for i in 1...(t+1) {
    let (dShare, pi) = try decPVSSShare(pubD: pubD, privC: comPrivKeys[i], pubC: comPubKeys[i], eShare: encShares[i])
    let goodShare = try verifyDecPVSSShare(pubD: pubD, pubC: comPubKeys[i], eShare: encShares[i], dShare: dShare, pi: pi)
    if (!goodShare) {
        print("BAD SHARE")
    } else {
        print("GOOD SHARE")
    }
}


