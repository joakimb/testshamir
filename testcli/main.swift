//
//  main.swift
//  testcli
//
//  Created by Joakim Brorsson on 2023-08-30.
//
import SwiftECC
import Foundation
import BigInt

//let domain = Domain.instance(curve: .EC256r1)
//toy domain
let domain = try Domain.instance(name: "EC29", p: BInt(29), a: BInt(4), b: BInt(20), gx: BInt(1), gy: BInt(5), order: BInt(37), cofactor: 1)
print("group order \(domain.order)")
// Rand int mod p
func randZp() -> BInt {
    return (domain.order - BInt.ONE).randomLessThan() + BInt.ONE
}

func toPoint(_ x: BInt) throws -> Point {
    return try domain.multiplyPoint(domain.g, x)
}

func gShamirShare(S: Point, t: Int, n: Int) throws -> (alphas: Array<BInt>, shares: Array<Point>) {
    
    var coeffs = Array<BInt>()
    coeffs.append(BInt(0))
    for _ in 1...(t) {
//        coeffs.append(randZp())
        coeffs.append(BInt(6))
    }
    print("coeffs", coeffs)
    
    var shares = Array<Point>()
    var alphas = Array<BInt>()//(1...n)
    for x in 1...n {
        let alpha = BInt(x)
        alphas.append(alpha)
        var sum = BInt(0)
        for i in 0...(coeffs.count-1) {
            sum += (coeffs[i] * alpha ** i).mod(domain.order)
        }
        //shares.append(S + sum)
        shares.append(try domain.addPoints(S, toPoint(sum)))
    }
    return (alphas, shares)
}

func lagX(alphas: Array<BInt>, i: Int) -> BInt {
    var prod = BInt(1)
    for j in 0...alphas.count-1 {
        if (i == j){ continue}
        let nom = BInt.ZERO - alphas[j]
        let den = alphas[i] - alphas[j]
        let frac = nom * den.modInverse(domain.order)
        prod *= frac.mod(domain.order)
    }
    return prod
}

func gShamirRec(shares: Array<Point>, t: Int, alphas: Array<BInt>) throws -> Point{
    
    if (alphas.count != t+1 || alphas.count != t+1) {
        throw NSError()
    }
    
    //var sum = BInt(0)
    var sum = try toPoint(BInt.ZERO)
    for i in 0...(alphas.count-1) {
//        print("term: "  , (lagX(alphas: alphas, i: i).mod(domain.order)), shares[i])
//        print("w", lagX(alphas: alphas, i: i).mod(domain.order) * shares[i].mod(domain.order))
        //sum +=  lagX(alphas: alphas, i: i).mod(domain.order) * shares[i].mod(domain.order)
        let lambda = lagX(alphas: alphas, i: i).mod(domain.order)
        let term = try domain.multiplyPoint(shares[i], lambda)
        
        sum = try domain.addPoints(sum, term)// <#T##p2: Point##Point#>)   * shares[i].mod(domain.order)
    }
    return sum
}

let t = 1// t+1 needed to reconstruct
let n = 3

//let S = BInt(34)
let S = try toPoint(BInt(34))
print("secret", S)

let sharing = try gShamirShare(S: S, t: t, n: n)
print("shares", sharing.shares)
let reconstruct = (alphas: Array(sharing.alphas[1...t+1]), shares: Array(sharing.shares[1...t+1]))
print("reconstruct shares", reconstruct.shares)
print("reconstruct indexes", reconstruct.alphas)
print("rec",try gShamirRec(shares: reconstruct.shares, t: t, alphas: reconstruct.alphas))
