//
//  main.swift
//  testcli
//
//  Created by Joakim Brorsson on 2023-08-30.
//
import SwiftECC
import Foundation
import BigInt

// setup
let t = 4// t+1 needed to reconstruct
let n = 8

let S = try toPoint(BInt(34))
print("secret", S)
let pp = setup(t: t,n: n)


//
//////test ECC shamir
//print("SSS+++++++++++++++++++++++++++++++++")
//let alphas = pp.alphas
//let shares = try gShamirShare(indexes: alphas, S: S, t: t, n: n)
//let ssreconstruct = (alphas: Array(alphas[2...t+2]), shares: Array(shares[1...t+1]))
//print("recreated",try gShamirRec(shares: ssreconstruct.shares, t: t, alphas: ssreconstruct.alphas))
//
////test schnorr fiat-shamir
//print("SCHNORR FS+++++++++++++++++++++++++++++++++")
//let x = BInt(5)
//let X = try toPoint(x)
//let y = BInt(6)
//let Y = try toPoint(y)
//let pi = try NIZKDLProve(x)
//print(pi)
//let valid = try NIZKDLVerify(X: X, pi: pi)
//print("true dl nizk:",valid)
//let invalid = try NIZKDLVerify(X: Y, pi: pi)
//print("false dl nizk:",invalid)
//
////test chaum-pedersen fiat-shamir
//print("CHAUM-PEDERSEN FS+++++++++++++++++++++++++++++++++")
//let exp = BInt(5)
//let a = try toPoint(randZp())
//let b = try toPoint(randZp())
//let A = try domain.multiplyPoint(a, exp)
//let B = try domain.multiplyPoint(b, exp)
//let Bad = try domain.multiplyPoint(b, BInt(6))
//let pieq = try NIZKDLEQProve(exp: exp, a: a, A: A, b: b, B: B)
//let valideq = try NIZKDLEQVerify(a: a, A: A, b: b, B: B, pi: pieq)
//print("true dleq nizk:",valideq)
//let invalideq = try NIZKDLEQVerify(a: a, A: A, b: b, B: Bad, pi: pieq)
//print("false dleq nizk:",invalideq)
//
////test resharenizk
//print("RESHARE NIZK FS+++++++++++++++++++++++++++++++++")
//let w1 = BInt(5)
//let w2 = BInt(7)
//let ga = try toPoint(randZp())
//let gb = try toPoint(randZp())
//let gc = try toPoint(randZp())
//let Y1 = try domain.multiplyPoint(ga, w1)
//let Y2 = try domain.multiplyPoint(ga, w2)
//let w2gb = try domain.multiplyPoint(gb, w2)
//let w1gc = try domain.multiplyPoint(gc, w1)
//let Y3 = try domain.subtractPoints(w2gb, w1gc)
//let pireshare = try NIZKReshareProve(w1: w1, w2: w2, ga: ga, gb: gb, gc: gc, Y1: Y1, Y2: Y2, Y3: Y3)
//let validreshare = try NIZKReshareVerify(ga: ga, gb: gb, gc: gc, Y1: Y1, Y2: Y2, Y3: Y3, pi: pireshare)
//let invalidreshare1 = try NIZKReshareVerify(ga: ga, gb: gb, gc: gc, Y1: Bad, Y2: Y2, Y3: Y3, pi: pireshare)
//let invalidreshare2 = try NIZKReshareVerify(ga: ga, gb: gb, gc: gc, Y1: Y1, Y2: Bad, Y3: Y3, pi: pireshare)
//let invalidreshare3 = try NIZKReshareVerify(ga: ga, gb: gb, gc: gc, Y1: Y1, Y2: Y2, Y3: Bad, pi: pireshare)
//print("true reshare nizk:",validreshare)
//print("false1 reshare nizk:",invalidreshare1)
//print("false2 reshare nizk:",invalidreshare2)
//print("false3 reshare nizk:",invalidreshare3)

//test DHPVSS
print("PVSS+++++++++++++++++++++++++++++++++")
struct Party {
    var comPrivKey: BInt
    var comPubKey: Point
    var distPrivKey: BInt
    var distPubKey: Point
    var reshares: Array<Point>?
    var reshareProof: ReshareProof?
}

// setup key for parties
let (firstPrivD,firstPubD) = try dKeyGen()
var parties = Array<Party>()

for _ in 1...pp.n {
    let (privKey, pubKey) = try keyGen()
    let (privD,pubD) = try dKeyGen()
    parties.append(Party(comPrivKey: privKey, comPubKey: pubKey.E, distPrivKey: privD, distPubKey: pubD))
}

let (encShares, piPvss) = try distributePVSS(pp: pp, privD: firstPrivD, pubD: firstPubD, comKeys: parties.map{$0.comPubKey}, S: S)

let validpvss = try verifyPVSS(pp: pp, pubD: firstPubD, C: encShares, comKeys: parties.map{$0.comPubKey}, pi: piPvss)
print("true pvss:",validpvss)
let invalidpvss = try verifyPVSS(pp: pp, pubD: S, C: encShares, comKeys: parties.map{$0.comPubKey}, pi: piPvss)
print("false pvss:",invalidpvss)

//decrypt
var decShares = Array<Point>()
for i in 0...(n-1) {
    let (dShare, pi) = try decPVSSShare(pubD: firstPubD, privC: parties.map{$0.comPrivKey}[i], pubC: parties.map{$0.comPubKey}[i], eShare: encShares[i])
    let goodShare = try verifyDecPVSSShare(pubD: firstPubD, pubC: parties.map{$0.comPubKey}[i], eShare: encShares[i], dShare: dShare, pi: pi)
    if (!goodShare) {
        print("BAD SHARE")
    } else {
        decShares.append(dShare)
        //print("GOOD SHARE")
    }
}
//reconstruct secret
let reconshares = Array(decShares[1...t+1])
let reconAlphas = Array(pp.alphas[2...t+2])
let reconstructedSecret = try recPVSS(shares:  reconshares, t: pp.t, alphas: reconAlphas)
print("shared:", S, "recon:", reconstructedSecret)

//new committee
let newPP = setup(t: pp.t, n: pp.n)
print("t",pp.t)
var newParties = Array<Party>()

for _ in 1...newPP.n {
    let (privKey, pubKey) = try keyGen()
    let (privD,pubD) = try dKeyGen()
    newParties.append(Party(comPrivKey: privKey, comPubKey: pubKey.E, distPrivKey: privD, distPubKey: pubD))
}

//reshare with pubD from original distributor
for i in 0...(pp.n-1) {
    
    // how to bootstrap th pk_D, just use pk_d of first sharing like this?
    let (reshares, pi) = try resharePVSS(partyIndex: i, comPrivKey: parties[i].comPrivKey, comPubKey: parties[i].comPubKey, partyPrivD: parties[i].distPrivKey, partyPubD: parties[i].distPubKey, curEncShares: encShares, prevPubD: firstPubD, nextComKeys: newParties.map{$0.comPubKey}, nextPP: newPP)
    
    parties[i].reshares = reshares
    parties[i].reshareProof = pi
    
}


//reconstruct shares from resharing
let newEncShares = Array<Point>()
for i in 0...(pp.n-1) {
    
    try reconstructResharesPVSS(partyIndex: i, curEncShares: encShares, reShares: parties[i].reshares!, nextComKeys: newParties.map{$0.comPubKey}, nextPP: newPP, prevPubD: newParties[i].distPubKey, curComKey: parties[i].comPubKey, pi: parties[i].reshareProof!)
    
}

//TOMORROW: its the pedersencheck that does not work. invesigate, maybe do by hand, and checkif U V and W are the same at both ends, and if the handleing of pk_D,L is correct.
//Also consider refactoring and renaming to make the code easier to reasno about to find the bug. AND CHECK IF THE BOOTSTRAPPING ASSUMPTION IF pk_D,L is bonkers (check if DL holds...).
//AND REMEMBER: it might be that the resharing i wrong, and not the proof. Thest this by doing the reconstruction and checking if you get the correct value. Also, mybe break up inte sub-functions.
// If nothing else works, it is possible to start a "by-hand" calculation from a set of encrypted shares (constructable from code) since that is the last point we know to be correct.

//print(parties)
//print(newParties)





//var comPubKeys = Array<Point>()
//var comPrivKeys = Array<BInt>()
//for _ in 1...n {
//    let (privKey, pubKey) = try keyGen()
//    comPubKeys.append(pubKey.E)
//    comPrivKeys.append(privKey)
//}


//TODO: make a second reshare with pubD derived from prev com pubD keys
////construct pk_{D,L_{r-1}}
//var reconKeys = Array<Point>()
//for i in curReconstructIndexes {
//
//    guard let index = i.asInt() else {
//        print("alpha too long")
//        exit(1)
//    }
//    reconKeys.append(pubDs[index])
//
//}
//let lagPubD = try lagPubD(keys: reconKeys, t: t, alphas:curReconstructIndexes)
