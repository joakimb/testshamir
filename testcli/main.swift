//
//  main.swift
//  testcli
//
//  Created by Joakim Brorsson on 2023-08-30.
//
import SwiftECC
import Foundation
import BigInt

//test ECC shamir
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

//test schnorr fiat shamir
let x = BInt(5)
let X = try toPoint(x)
let y = BInt(6)
let Y = try toPoint(y)
let pi = try NIZKDLProve(x)
print(pi)
let valid = try NIZKDLVerify(X: X, u: pi.u, c: pi.c, z: pi.z)
print("valid dl nizk:",valid)
let invalid = try NIZKDLVerify(X: Y, u: pi.u, c: pi.c, z: pi.z)
print("invalid dl nizk:",invalid)
