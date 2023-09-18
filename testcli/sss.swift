//
//  sss.swift
//  testcli
//
//  Created by Joakim Brorsson on 2023-09-18.
//

import Foundation
import SwiftECC
import BigInt

func gShamirShare(alphas: Array<BInt>, S: Point, t: Int, n: Int) throws -> Array<Point> {
    
    var coeffs = Array<BInt>()
    coeffs.append(BInt(0))
    for _ in 1...(t) {
        coeffs.append(randZp())
    }
    
    var shares = Array<Point>()
    for x in 1...n {
        let alpha = alphas[x]
        print(alpha)
        var sum = BInt(0)
        for i in 0...(coeffs.count-1) {
            sum += (coeffs[i] * alpha ** i).mod(domain.order)
        }
        shares.append(try domain.addPoints(S, toPoint(sum)))
    }
    return shares
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
    
    var sum = try toPoint(BInt.ZERO)
    for i in 0...(alphas.count-1) {
        let lambda = lagX(alphas: alphas, i: i).mod(domain.order)
        let term = try domain.multiplyPoint(shares[i], lambda)
        sum = try domain.addPoints(sum, term)// <#T##p2: Point##Point#>)   * shares[i].mod(domain.order)
    }
    return sum
}
