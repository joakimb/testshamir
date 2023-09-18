//
//  helpers.swift
//  testcli
//
//  Created by Joakim Brorsson on 2023-09-18.
//

import Foundation
import BigInt
import SwiftECC

//let domain = Domain.instance(curve: .EC256r1)
let domain = { () -> Domain in
    do {
        return try Domain.instance(name: "EC29", p: BInt(29), a: BInt(4), b: BInt(20), gx: BInt(1), gy: BInt(5), order: BInt(37), cofactor: 1)
    } catch {
        print("domain error")
        return Domain.instance(curve: .EC256r1)
    }
}()

// Rand int mod p
func randZp() -> BInt {
    return BInt(5)
    //return (domain.order - BInt.ONE).randomLessThan() + BInt.ONE
}

func toPoint(_ x: BInt) throws -> Point {
    return try domain.multiplyPoint(domain.g, x)
}

