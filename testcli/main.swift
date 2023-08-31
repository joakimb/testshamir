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

// Rand int mod p
func randZp() -> BInt {
    return (domain.order - BInt.ONE).randomLessThan() + BInt.ONE
}

func toPoint(x: BInt) throws -> Point {
    return try domain.multiplyPoint(domain.g, x)
}


//Diffie Hellman experiment
//let r = randZp()
//print("r", r)
//let R = try toPoint(domain: domain, x: r)
//print("R", R)
//
//let a = BInt(1)
//let b = BInt(2)
//let A = try toPoint(domain: domain, x: a)
//let B = try toPoint(domain: domain, x: b)
//
//let dh1 = try domain.multiplyPoint(A, b)
//let dh2 = try domain.multiplyPoint(B, a)
//print("dh1", dh1)
//print("dh2", dh2)

func gShamirShare(S: Point, t: Int, n: Int) throws -> Array<Point> {
    
    var coeffs = Array<BInt>()
//    for _ in 0...(t) {
//        coeffs.append(randZp())
//    }
    coeffs.append(BInt(5))
    coeffs.append(BInt(6))
    
    var shares = Array<Point>()
    for x in 0...n {
        var evalpoly = coeffs.enumerated()
            .map{ (i,coeff) in coeff * BInt(x) ** i } //build terms of polynomial evaluated at x
            .reduce(BInt(0),+) //sum them up
        let share = try domain.addPoints(S, toPoint(x:evalpoly))
        shares.append(share)
    }
    return shares
}

func lagX(indexes: Array<Int>, i: Int) -> BInt {
    var prod = 1
    for j in indexes {
        if (i == j){ continue}
        let nom = indexes[0] - indexes[j]
        let den = indexes[i] - indexes[j]
        prod *= nom / den
        print(String(i) + ": nom : " + String(nom))
        print(String(i) + ": den : "  + String(den))
        print(String(i) + ": nom/den : " + String(nom/den))
    }
    print("lambda_" + String(i) + " : " + String(prod))
    return BInt(prod)
}

func gShamirRec(shares: Array<Point>, t: Int, indexes: Array<Int>) throws -> Point {
    
    if (indexes.count != t+1 || shares.count != t+1) {
        throw NSError()
    }
    
    let S = try zip(indexes,shares)
        .map{(i, share) in
            try domain.multiplyPoint(share, lagX(indexes: indexes, i: i))
        }
        .reduce(try toPoint(x:BInt.ZERO), {(x: Point, y: Point) in try domain.addPoints(x,y)}) //sum
    return S
}

let t = 1
let n = 2
let secret = try toPoint(x: BInt(1))

let shares = try gShamirShare(S: secret, t: t, n: n)
print("secret", secret)
print("shares", shares)
print("reconstruct with",shares[0...t])
let indexes = Array(0...t)
print("indexes", indexes)

print("rec",try gShamirRec(shares: Array(shares[0...t]), t: t, indexes: indexes))
