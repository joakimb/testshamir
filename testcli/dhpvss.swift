//
//  dhpvss.swift
//  testcli
//
//  Created by Joakim Brorsson on 2023-09-18.
//

import Foundation
import BigInt

func setup() -> (Array<BInt>) {
    
    var alphas = Array<BInt>()//(0...n)
    alphas.append(BInt(0))
    for x in 1...n {
        let alpha = BInt(x)
        alphas.append(alpha)
    }
    
    //continue here, with doing vi:s, but do on paper at same time
    
    return alphas
}
