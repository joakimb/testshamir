//
//  helpers.swift
//  testcli
//
//  Created by Joakim Brorsson on 2023-09-18.
//

import Foundation
import BigInt
import SwiftECC

let debug = true

let domain: Domain = {
    if debug {
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

let byteBufLen: Int = {
    if debug {
        return 1
    } else {
        return 32
    }
}()

// Rand int mod p
func randZp() -> BInt {
    if debug {
        return BInt(5)
    } else {
        return (domain.order - BInt.ONE).randomLessThan() + BInt.ONE
    }
}

func toPoint(_ x: BInt) throws -> Point {
    return try domain.multiplyPoint(domain.g, x)
}

func toBytes(_ point: Point) -> Array<UInt8> {
    //we represent a curve point (x,y) as bytes(x)||bytes(y) (uncompressed point representation)
    
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
