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
let t = 1// t+1 needed to reconstruct
let n = 4

let S = try toPoint(randZp())
print("secret", S)
let pp = setup(t: t,n: n)
let Bad = try domain.multiplyPoint(domain.g, BInt(6))


//////test ECC shamir
//print("SSS+++++++++++++++++++++++++++++++++")
//let alphas = pp.alphas
//let shares = try gShamirShare(indexes: alphas, S: S, t: t, n: n)
//let ssreconstruct = (alphas: Array(alphas[2...t+2]), shares: Array(shares[1...t+1]))
//print("recreated",try gShamirRec(shares: ssreconstruct.shares, t: t, alphas: ssreconstruct.alphas))

//test schnorr fiat-shamir
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
//
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
let reconshares = Array(decShares[1...1+t])
let reconAlphas = Array(pp.alphas[2...1+t+1])

print("calling reconstruct with indexes:")
for index in reconAlphas {
    print(index)
}
for share in reconshares {
    print(share)
}


let reconstructedSecret = try recPVSS(shares:  reconshares, t: pp.t, alphas: reconAlphas)
print("shared:", S, "recon:", reconstructedSecret)

//new committee
let newPP = setup(t: pp.t, n: pp.n)
//print(pp.t,pp.n,newPP)
var newParties = Array<Party>()

for _ in 1...newPP.n {
    let (privKey, pubKey) = try keyGen()
    let (privD,pubD) = try dKeyGen()
    newParties.append(Party(comPrivKey: privKey, comPubKey: pubKey.E, distPrivKey: privD, distPubKey: pubD))
}

//reshare with pubD from original distributor
print("reshare:")
for i in 0...(pp.n-1) {
    
    // how to bootstrap th pk_D, just use pk_d of first sharing like this?
    let (reshares, pi) = try resharePVSS(partyIndex: i, comPrivKey: parties[i].comPrivKey, comPubKey: parties[i].comPubKey, partyPrivD: parties[i].distPrivKey, partyPubD: parties[i].distPubKey, curEncShares: encShares, prevPubD: firstPubD, nextComKeys: newParties.map{$0.comPubKey}, nextPP: newPP)
    
    parties[i].reshares = reshares
    parties[i].reshareProof = pi
    
}

// validate resharing
var validReshareIndexes = Array<Int>()
for i in 0...(pp.n-1) {
    
    let validReshare = try verifyReshare(partyIndex: i, curEncShares: encShares, encReshares: parties[i].reshares!, nextComKeys: newParties.map{$0.comPubKey}, nextPP: newPP, prevPubD:firstPubD, reshareComKey: parties[i].comPubKey, reshareDistKey: parties[i].distPubKey, pi: parties[i].reshareProof!)
    
    
    if (validReshare) {
        validReshareIndexes.append(i+1)
    }
    
}
if (validReshareIndexes.count == pp.n){
    print("GOOD reshare:",validReshareIndexes);
} else {
    print("BAD reshare");
} // we trust this now

let selectedReconIndexes = Array(validReshareIndexes[0...newPP.t])// first t+1 valid reshares
print("selected_ind",selectedReconIndexes)

//reconstruct shares from resharing
var selectedReconParties = Array<Party>()
for i in selectedReconIndexes {
    //let ind = selectedReconIndexes[i-1]
    let selected_party = parties[i-1]
    selectedReconParties.append(selected_party)
    //print("LKJHLJ:G",i,ind)
}

print("PARTIES",parties)

print("PARTYRESHARES", selectedReconParties.map{$0.reshares})

//extract the correct reshares for each party
var selectedReconShares = [[Point]](repeating: [Point](repeating: zeroPoint, count: selectedReconParties.count), count: newPP.n)
for i in 0...selectedReconParties.count-1 {
    for j in 0...newPP.n-1 {
        let share_j_from_ith_selected_party = selectedReconParties[i].reshares![j]
        selectedReconShares[j][i] = share_j_from_ith_selected_party
    }
}

print("EXTRACTED RESHARES",selectedReconShares)
var reconstructedReshares = Array<Point>()
for j in 0...(newPP.n-1) {
    
    reconstructedReshares.append(try reconstructReshare(pp: newPP, selectedIndexes:  selectedReconIndexes, selectedEncReshares: selectedReconShares[j]))
    
}
print("recaon",reconstructedReshares)

//AFTER COFFEE CINTINUE HERE

//interpolate key for selected group L of reshares
var reconDistPubKeys = Array<Point>()
for i in selectedReconIndexes {
    reconDistPubKeys.append(parties[i-1].distPubKey)
//    reconDistPubKeys.append(parties[i-1].comPubKey) // TODO, this should ruin th proofs, but i doesnt
    print("FRIDAY! THIS SHOULD NOT WORK!!!")
//    reconDistPubKeys.append(parties[i].distPubKey)
}
var alphas = selectedReconIndexes.map{BInt($0)}
print("alpphas",alphas)
let prevPubD = try lagPubD(keys: reconDistPubKeys, t: pp.t, alphas: alphas)
print("FRIDAY: prevPubD should NOT be reconstrcted from any parties like this, only from the ones which are \"used\" in reconstruction. FIX")

//decrypt reconstructred shares
var decRenconShares = Array<Point>()
for i in 0...(newPP.n-1) {
    let (dReShare, repi) = try decPVSSShare(pubD: prevPubD, privC: newParties[i].comPrivKey, pubC: newParties[i].comPubKey, eShare: reconstructedReshares[i])
    let goodShare = try verifyDecPVSSShare(pubD: prevPubD, pubC: newParties[i].comPubKey, eShare: reconstructedReshares[i], dShare: dReShare, pi: repi)
    if (!goodShare) {
        print("BAD SHARE")
    } else {
        decRenconShares.append(dReShare)
        print("GOOD SHARE!")
    }
}

//reconstruct secret again
let reconReshares = Array(decRenconShares[1...t+1])
let reconReAlphas = Array(newPP.alphas[2...t+2])
print("RECONRESHARE indexes")
for i in 0...reconReshares.count-1 {
    print(reconReAlphas[i])
}
print("RECONRESHARE shares")
for i in 0...reconReshares.count-1 {
    print(reconReshares[i])
}
let reconstructedReSecret = try recPVSS(shares:  reconReshares, t: newPP.t, alphas: reconReAlphas)
print("shared:", S, "reconreshares:", reconstructedReSecret)


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
