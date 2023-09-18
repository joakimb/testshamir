//
//  main.swift
//  testcli
//
//  Created by Joakim Brorsson on 2023-08-30.
//
import SwiftECC
import Foundation
import BigInt


let t = 10// t+1 needed to reconstruct
let n = 30

let S = try toPoint(BInt(34))
print("secret", S)
let sharing = try gShamirShare(S: S, t: t, n: n)
let reconstruct = (alphas: Array(sharing.alphas[1...t+1]), shares: Array(sharing.shares[1...t+1]))
print("recreated",try gShamirRec(shares: reconstruct.shares, t: t, alphas: reconstruct.alphas))
