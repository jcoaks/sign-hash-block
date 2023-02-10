const fs = require("fs");
const crypto = require("crypto");
const { Crypto } = require("@peculiar/webcrypto");
const express= require('express')

const app = express()
const cryptosubtle = new Crypto();
const subtle = cryptosubtle.subtle;

let keyPairs = {};

const port = 3000;

app.use(express.urlencoded({
    extended: true
}));

app.post('/sign-block', function(req, res) {
    let signature64 = sign(req.body)
    signature64.then(function(res2) {
        console.log(res2)
        res.json({"signature": res2})
      }
    )
});

app.post('/generate-hash', function(req, res) {
    let hash0 = generateHash(req.body)
    console.log(hash0)
    res.json({"hash": hash0})
});

function generateHash(params) {
    let blockToSign = {
        prevHash: params.prevHash,
        height: parseInt(params.height),
        version: parseInt(params.version),
        data: params.data,
        timestamp: parseInt(params.timestamp),
        scope: params.scope,
        signature: params.signature,
        by: params.by,
        rootPrevHash: params.rootPrevHash,
        rootHeight: parseInt(params.rootHeight)
    };
    console.log(blockToSign)
    var hash = crypto.createHash("sha256");
    const data = hash.update(JSON.stringify(blockToSign));
    return data.digest("hex");
}

async function sign(params){
    let blockToSign = {
        prevHash: params.prevHash,
        height: parseInt(params.height),
        version: parseInt(params.version),
        data: params.data,
        timestamp: parseInt(params.timestamp),
        scope: params.scope,
        by: params.by
    };

    console.log(blockToSign);

    const algorithmParameters = {
        name: "RSA-PSS",
        saltLength: 32,
    };

    let signature0 = await subtle.sign(
        algorithmParameters,
        await getPrivateKey(params.by),
        Buffer.from(JSON.stringify(blockToSign, null, 2))
    );

    let signature_verified = await subtle.verify(
        algorithmParameters,
        await getPublicKey(params.by),
        signature0,
        Buffer.from(JSON.stringify(blockToSign, null, 2))
    );
    console.log(signature_verified)

    let signature64 = Buffer.from(signature0).toString("base64");
    return signature64
}

async function getPrivateKey(WHO) {
    if (!keyPairs[WHO]) {
        let privateKeyFile
        try {
            var WHO0 = WHO.replace("/", "-");
            privateKeyFile = fs.readFileSync(`./KEYS/${WHO0.toUpperCase()}.key`).toString();
        } catch (err) {
            throw Error("Private key for " + WHO + " was not found.")
        }

        keyPairs[WHO] =  subtle.importKey(
        "pkcs8",
        pemToArrayBufferPrivate(privateKeyFile),
        {
            name: "RSA-PSS",
            hash: { name: "SHA-256" },
        },
        false,
        ["sign"]
        );
    }
    
    return keyPairs[WHO] 
}


async function getPublicKey(WHO) {
    let publicKeyFile
    try {
        var WHO0 = WHO.replace("/", "-");
        publicKeyFile = fs.readFileSync(`./KEYS/${WHO0.toUpperCase()}.pub.key`).toString();
    } catch (err) {
        throw Error("Public key for " + WHO + " was not found.")
    }

    publicKey =  subtle.importKey(
    "spki",
    pemToArrayBufferPublic(publicKeyFile),
    {
        name: "RSA-PSS",
        hash: { name: "SHA-256" },
    },
    false,
    ["verify"]
    );
    
    return publicKey 
}

function pemToArrayBufferPrivate(pem) {
    var b64Lines = pem.replace("\n", "");
    var b64Prefix = b64Lines.replace("-----BEGIN RSA PRIVATE KEY-----", "");
    var b64Final = b64Prefix.replace("-----END RSA PRIVATE KEY-----", "");
    return base64ToArrayBuffer(b64Final);
}

function pemToArrayBufferPublic(pem) {
  var b64Lines = pem.replace("\n", "");
  var b64Prefix = b64Lines.replace("-----BEGIN PUBLIC KEY-----", "");
  var b64Final = b64Prefix.replace("-----END PUBLIC KEY-----", "");

  return base64ToArrayBuffer(b64Final);
}

function base64ToArrayBuffer(b64) {
    var byteString = atob(b64);
    var byteArray = new Uint8Array(byteString.length);
    for (var i = 0; i < byteString.length; i++) {
      byteArray[i] = byteString.charCodeAt(i);
    }
    return byteArray;
}
  
app.listen(port, () => {});