//
//  helpers.swift
//  testcli
//
//  Created by Joakim Brorsson on 2023-09-18.
//

import Foundation
import BigInt
import SwiftECC

//debug helpers
let smallCurve = false
let notRandom = false

let domain: Domain = {
    
    if smallCurve {
        
        do {
            
            return try Domain.instance(name: "EC29", p: BInt(29), a: BInt(4), b: BInt(20), gx: BInt(1), gy: BInt(5), order: BInt(37), cofactor: 1)
            
        } catch {
            
            print("domain error")
            return Domain.instance(curve: .EC256r1)
            
        }
        
    } else {
        
        return Domain.instance(curve: .EC256r1)
        
    }
    
}()

let zeroPoint = {
    do {
        return try toPoint(BInt(0))
    } catch {
        print("zero point error")
        return domain.g
    }
}()

let byteBufLen: Int = {
    
    if smallCurve {
        
        return 1
        
    } else {
        
        return 32
        
    }
    
}()

// Rand int mod p
func randZp() -> BInt {
    
    if notRandom {
        
        return BInt(5)
        
    } else {
        
        return (domain.order - BInt.ONE).randomLessThan() + BInt.ONE
        
    }
    
}

func toPoint(_ x: BInt) throws -> Point {
    return try domain.multiplyPoint(domain.g, x)
}

//we represent a curve point (x,y) as bytes(x)||bytes(y) (uncompressed point representation)
func toBytes(_ point: Point) -> Array<UInt8> {
    
    var xBytes: Bytes = point.x.asSignedBytes()
    var yBytes: Bytes = point.y.asSignedBytes()
    
    //pad if needed
    while xBytes.count < byteBufLen {
        
        xBytes.insert(UInt8(0), at: 0)
        
    }
    
    while yBytes.count < byteBufLen {
        
        yBytes.insert(UInt8(0), at: 0)
        
    }
    
    //trim if needed
    var first = xBytes.count - byteBufLen
    var last = xBytes.count - 1
    var trimmedXBytes = Array<UInt8>(xBytes[first...last])
    
    first = yBytes.count - byteBufLen
    last = yBytes.count - 1
    var trimmedYBytes = Array<UInt8>(yBytes[first...last])
    
    let bytes = trimmedXBytes + trimmedYBytes
    
    return bytes
    
}

func sha256(_ bytes: Array<UInt8>) -> BInt {
   
    let data = Data(bytes)//byte buffer
    let hash = data.sha256()
    let hashstring: String = hash.toHexString()
    let radix: Int = 16
    let binthash = BInt(hashstring, radix: radix)
    
    return binthash!
    
}

func hashToPolyCoeffs(data: Array<UInt8>, degree: Int) -> Array<BInt> {
    
    //let the seed be the hash of the input and the i:th coefficient be defined as the seed hashed i times
    var coeffs = Array<BInt>()
    var seed = sha256(data).mod(domain.order)
    
    for _ in 0...degree {
        
        coeffs.append(seed)
        seed = sha256(seed.asSignedBytes()).mod(domain.order)
        
    }
    
    return coeffs
    
}

func genScrapeSumTerms(n: Int, evalPoints: Array<BInt>, codeCoeffs: Array<BInt>, polyCoeffs: Array<BInt>) throws -> Array<BInt> {
    
    var terms = Array<BInt>()
    
    for x in 1...(n) {
        
        let evalPoint = evalPoints[x]
        var polyEval = BInt(0)
        
        for i in 0...(polyCoeffs.count-1) {
            
            polyEval += (polyCoeffs[i] * evalPoint ** i).mod(domain.order)
            
        }
        
        let term = (codeCoeffs[x - 1] * polyEval).mod(domain.order)
        terms.append(term)
        
    }
    
    return terms
    
}
