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
//let t = 1// t+1 needed to reconstruct
//let n = 3
//
//let S = try toPoint(BInt(34))
//print("secret", S)
//let pp = setup()
//let alphas = pp.alphas
//print(alphas)
//let shares = try gShamirShare(indexes: alphas, S: S, t: t, n: n)
//print(share
//let reconstruct = (alphas: Array(alphas[2...t+2]), shares: Array(shares[1...t+1]))
//print("recreated",try gShamirRec(shares: reconstruct.shares, t: t, alphas: reconstruct.alphas))

//test schnorr fiat-shamir
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
let t = 1// t+1 needed to reconstruct
let n = 3

let S = try toPoint(BInt(34))
print("secret", S)
let pp = setup(t: t,n: n)
let (privD,pubD) = try dKeyGen()
var comKeys = Array<Point>()
for _ in 1...n {
    let (_, pubKey) = try keyGen()
    comKeys.append(pubKey.E)
}
let (encShares, piPvss) = try distributePVSS(pp: pp, privD: privD, pubD: pubD, comKeys: comKeys, S: S)

let validpvss = try verifyPVSS(pp: pp, pubD: pubD, C: encShares, comKeys: comKeys, pi: piPvss)
print("true pvss:",validpvss)
let invalidpvss = try verifyPVSS(pp: pp, pubD: S, C: encShares, comKeys: comKeys, pi: piPvss)
print("false pvss:",invalidpvss)
