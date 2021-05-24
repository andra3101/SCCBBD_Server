import express from 'express'
import cors from 'cors'
import * as bigintConversion from 'bigint-conversion'
import * as paillierBigint from 'paillier-bigint'
import * as rsa from './rsa'
import * as aes from './aes'

//Var
const port = 3000
let keyRSA: rsa.rsaKeyPair


//SERVER
const app = express()
app.use(cors({
  origin: 'http://localhost:4200' // angular.js server
}), express.json())

app.get('/', (req, res) => {
  res.send('hello world')
})
app.get('/rsa', async function (req, res) {
    if (keyRSA === undefined)
      keyRSA = await rsa.generateKeys(2048)
  
    res.json({
      eHex: bigintConversion.bigintToHex(keyRSA.publicKey.e),
      nHex: bigintConversion.bigintToHex(keyRSA.publicKey.n)
    })
  })
app.get('/cifradoHomomorfico', async function(req, res) {
   // (asynchronous) creation of a random private, public key pair for the Paillier cryptosystem
  const { publicKey, privateKey } = await paillierBigint.generateRandomKeys(3072)

  // Optionally, you can create your public/private keys from known parameters
  // const publicKey = new paillierBigint.PublicKey(n, g)
  // const privateKey = new paillierBigint.PrivateKey(lambda, mu, publicKey)

  const m1 = 12345678901234567890n
  const m2 = 5n

  // encryption/decryption
  const c1 = publicKey.encrypt(m1)
  console.log(privateKey.decrypt(c1)) // 12345678901234567890n

  // homomorphic addition of two ciphertexts (encrypted numbers)
  const c2 = publicKey.encrypt(m2)
  const encryptedSum = publicKey.addition(c1, c2)
  console.log(privateKey.decrypt(encryptedSum)) // m1 + m2 = 12345678901234567895n

  // multiplication by k
  const k = 10n
  const encryptedMul = publicKey.multiply(c1, k)
  console.log(privateKey.decrypt(encryptedMul)) // k · m1 = 123456789012345678900n
    res.json({
      mensaje: "EN PROCESO"
    })
  })

  app.listen(port, function () {
    console.log(`Listening on http://localhost:${port}`)
  })