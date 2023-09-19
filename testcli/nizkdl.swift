//
//  nizkdl.swift
//  testcli
//
//  Created by Joakim Brorsson on 2023-09-19.
//

import Foundation
import BigInt
import SwiftECC
//fiat schamir schnorr from:
//https://crypto.stanford.edu/cs355/19sp/lec5.pdf

func NIZKDLProve(x: BInt) throws -> (u: Point, c: BInt, z: BInt){

    let X = try toPoint(x)
    let r = randZp()
    let u = try toPoint(r)
    let bytes = toBytes(domain.g) + toBytes(X) + toBytes(u)
    let c = sha256(bytes)
    let z = r + c * x
    
    return (u: u, c: c, z: z)

}

//func NIZKDLVerify(X: Point, u: Point, c: BInt, z: BInt){
//    
//    let bytes = toBytes(domain.g) + toBytes(X) + toBytes(u)
//    let cprime = sha256(bytes)
//    
//    return (c == cprime) && 
//    
//}
