const express = require("express")
const S = require("@emurgo/cardano-serialization-lib-nodejs")
const MS = require("@emurgo/cardano-message-signing-nodejs")

const app = express()
app.use(express.json())

const PAYLOAD = "736667393837773334656e6764666a646865776f6533333333766476" //this is the hexidecimal message that the user will be signing. It should be generated each time a user requests to be verified and be stored in a DB with their address.

/**
 * Determines if a wallet address signed a message (payload)
 * @param address Serialized wallet address
 * @param payload Serialized payload (i.e. message with nonce)
 * @param coseSign1Hex Hex string of signed payload (signed by user"s wallet)
 * @returns true if payload was signed by wallet address
 */
const verify = (address, payload=PAYLOAD, coseSign1Hex) => {
  const coseSign1 = MS.COSESign1.from_bytes(Buffer.from(coseSign1Hex.signature, "hex"))
  const payloadCose = coseSign1.payload()

  if (!verifyPayload(payload, payloadCose))
    throw new Error("Payload does not match")

  const protectedHeaders = coseSign1.headers().protected().deserialized_headers()
  const addressCose = S.Address.from_bytes(
    protectedHeaders.header(MS.Label.new_text("address")).as_bytes()
  )

  const coseKey = MS.COSEKey.from_bytes(Buffer.from(coseSign1Hex.key, "hex"));
  const publicKeyCose = S.PublicKey.from_bytes(coseKey.header(
    MS.Label.new_int(
      MS.Int.new_negative(MS.BigNum.from_str("2"))
    )).as_bytes()
  );
  
  if (!verifyAddress(address, addressCose, publicKeyCose))
    throw new Error("Could not verify because of address mismatch")

  const signature = S.Ed25519Signature.from_bytes(coseSign1.signature())
  const data = coseSign1.signed_data().to_bytes()
  return publicKeyCose.verify(data, signature)
}

const verifyPayload = (payload, payloadCose) => {
  return Buffer.from(payloadCose).compare(Buffer.from(payload, "hex")) === 0
}

const verifyAddress = (address, addressCose, publicKeyCose) => {
  const checkAddress = S.Address.from_bytes(Buffer.from(address, "hex"))
  if (addressCose.to_bech32() === checkAddress.to_bech32()) {
   return true
  }
  // check if BaseAddress
  try {
    const baseAddress = S.BaseAddress.from_address(addressCose)
    //reconstruct address
    const paymentKeyHash = publicKeyCose.hash()
    const stakeKeyHash = baseAddress.stake_cred().to_keyhash()
    const reconstructedAddress = S.BaseAddress.new(
      checkAddress.network_id(),
      S.StakeCredential.from_keyhash(paymentKeyHash),
      S.StakeCredential.from_keyhash(stakeKeyHash)
    )

    if (checkAddress.to_bech32() === reconstructedAddress.to_address().to_bech32()) {
      return true
    }
  } catch (e) {
    throw e
  }
  // check if RewardAddress
  try {
    //reconstruct address
    const stakeKeyHash = publicKeyCose.hash()
    const reconstructedAddress = S.RewardAddress.new(
      checkAddress.network_id(),
      S.StakeCredential.from_keyhash(stakeKeyHash)
    )
    if (checkAddress.to_bech32() === reconstructedAddress.to_address().to_bech32()) {
      return true
    }
  } catch (e) {
    throw e
  }

  return false
}


app.get("/", (req, res) => {
  res.sendFile(__dirname + "/frontend/home.html")
})

app.post("/verify", (req, res) => {
  console.log(req.body)
  const isValid = verify(req.body.address, PAYLOAD, req.body.signature)
  res.send({status: 200, result: isValid})
})

app.get("/payload", (req, res) => {
  res.json({status: 200, payload: PAYLOAD})
})

app.listen(8000, () => {
  console.log("listening on port 8000")
})