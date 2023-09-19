//
//  main.swift
//  testcli
//
//  Created by Joakim Brorsson on 2023-08-30.
//
import SwiftECC
import Foundation
import BigInt


//let t = 1// t+1 needed to reconstruct
//let n = 3
//
//let S = try toPoint(BInt(34))
//print("secret", S)
//let pp = setup()
//let alphas = pp.alphas
//print(alphas)
//let shares = try gShamirShare(indexes: alphas, S: S, t: t, n: n)
//print(shares)
//let reconstruct = (alphas: Array(alphas[2...t+2]), shares: Array(shares[1...t+1]))
//print("recreated",try gShamirRec(shares: reconstruct.shares, t: t, alphas: reconstruct.alphas))

let pi = try NIZKDLProve(x: BInt(5))
print(pi)
