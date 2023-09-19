//
//  dhpvss.swift
//  testcli
//
//  Created by Joakim Brorsson on 2023-09-18.
//

import Foundation
import BigInt
import SwiftECC
import CryptoSwift

func setup( n: Int) -> (alphas: Array<BInt>, vs: Array<BInt>) {
    
    var alphas = Array<BInt>()//(0...n)
    alphas.append(BInt(0))
    for x in 1...n {
        let alpha = BInt(x)
        alphas.append(alpha)
    }
    
    var vs = Array<BInt>()
    for i in 1...n {
        
        var v = BInt(1)
        
        for j in 1...n {
            
            if (i == j){
                continue
            }
            
            v = alphas[i] - alphas[j]
            v = v.modInverse(domain.order)
            
        }
        
        vs.append(v)
        
    }
    
    return (alphas, vs)
}

func dKeyGen() throws  -> (privD: BInt, pubD: Point) {
    
    let privD = randZp()
    let pubD = try toPoint(privD)
    
    return (privD,pubD)
}




//func keyGen() //skipping "id" parameter in omega, seems unused
