const express = require('express')
const cookieParser = require("cookie-parser");
const {KmsKeyringNode, CommitmentPolicy, buildClient} = require("@aws-crypto/client-node");
const {encrypt, decrypt} = buildClient(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)


const app = express()
app.use(cookieParser())

const generatorKeyId = 'arn:aws:kms:us-east-1:************:key/9b2938aa-fb2d-44ed-a598-39b5270abaa6'
const keyring = new KmsKeyringNode({generatorKeyId})
const cookieName = 'encrypted'

// https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/js-examples.html

app.get('/encrypt', async function (req, res) {
    const plaintext = Math.random().toString()
    const encrypted = await encrypt(keyring, plaintext)

    res.cookie(cookieName, encrypted.result)
    res.send(plaintext)
})

app.get('/decrypt', async function (req, res) {
    const encrypted = req.cookies[cookieName]
    const decrypted = await decrypt(keyring, Uint8Array.from(Buffer.from(encrypted)))
    res.send(decrypted.plaintext.toString())
})

app.listen(3000)
