

async function generateAll() {
    generateSender();
    generateReceiver1();
    generateReceiver2();
    generateMaster();
}

async function generateSender() {
    var sender = bsv.HDPrivateKey.fromRandom();
    document.getElementById('sender_priv').value = sender.toString();
}

async function generateReceiver1() {
    var receiver1 = bsv.HDPrivateKey.fromRandom();
    document.getElementById('receiver1_priv').value = receiver1.toString();

    var receiver1_pub = bsv.HDPublicKey.fromHDPrivateKey(receiver1);
    document.getElementById('receiver1_pub').value = receiver1_pub.toString();
}

async function generateReceiver2() {
    var receiver2 = bsv.HDPrivateKey.fromRandom();
    document.getElementById('receiver2_priv').value = receiver2.toString();

    var receiver2_pub = bsv.HDPublicKey.fromHDPrivateKey(receiver2);
    document.getElementById('receiver2_pub').value = receiver2_pub.toString();
}

async function generateMaster() {
    var master_secret = window.crypto.getRandomValues(new Uint8Array(32));
    document.getElementById('master_key').innerHTML = toHexString(master_secret);
}

async function generateEncryptMessage() {
    var key_data = toByteArray(document.getElementById('master_key').innerHTML);
    var key = await window.crypto.subtle.digest(
        {
            name: "SHA-256",
        },
        new Uint8Array(key_data)
    );

    var message = document.getElementById('message').value;
    var message_data = new TextEncoder().encode(message);
    var encrypted_message = await encrypt(key, message_data);
    document.getElementById('message_iv').innerHTML = toHexString(encrypted_message[0]);
    document.getElementById('encrypted_message').innerHTML = toHexString(new Uint8Array(encrypted_message[1]));
}

async function encryptReceiver1() {
    var senderPriv = bsv.HDPrivateKey.fromString(document.getElementById('sender_priv').value).privateKey;
    var receiver1Pub = bsv.HDPublicKey.fromString(document.getElementById('receiver1_pub').value).publicKey;
    var key = await dhKey(senderPriv, receiver1Pub);
    document.getElementById('sender_receiver1_ecdh').innerHTML = toHexString(key);

    var master_key = toByteArray(document.getElementById('master_key').innerHTML);

    var encrypted = await encrypt(key, master_key);
    document.getElementById('receiver1_IV').innerHTML = toHexString(encrypted[0]);
    document.getElementById('receiver1_encrypted_key').innerHTML = toHexString(encrypted[1]);
}

async function dhKey(privateKey, publicKey) {

    // Convert keys from ECDSA to ECDH
    // var privdata = await window.crypto.subtle.exportKey("raw", privateKey);
    var privBuffer = privateKey.toBuffer();
    console.log("privBuffer")
    console.log(privBuffer)
    var der = new Uint8Array(privBuffer.length + 1)
    // der[0] = 0 // Set first byte zero
    // der.set(privBuffer, 1)
    // console.log("der")
    // console.log(der)
    var privkey = await window.crypto.subtle.importKey(
        "raw", privBuffer,
        {   //these are the algorithm options
            name: "ECDH",
            namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
        },
        false, //whether the key is extractable (i.e. can be used in exportKey)
        ["deriveKey", "deriveBits"] //"deriveKey" and/or "deriveBits" for private keys only (just put an empty list if importing a public key)
    )
    // console.log("privkey");
    // console.log(privkey);

    // var pubdata = await window.crypto.subtle.exportKey("spki", publicKey);
    var pubkey = await window.crypto.subtle.importKey(
        "spki", publicKey.toDER(),
        {   //these are the algorithm options
            name: "ECDH",
            namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
        },
        false, //whether the key is extractable (i.e. can be used in exportKey)
        [] //"deriveKey" and/or "deriveBits" for private keys only (just put an empty list if importing a public key)
    )
    // console.log("pubkey");
    // console.log(pubkey);

    var secret = await window.crypto.subtle.deriveBits(
        {
            name: "ECDH",
            namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
            public: pubkey, //an ECDH public key from generateKey or importKey
        },
        privkey, //your ECDH private key from generateKey or importKey
        256 //the number of bits you want to derive
    );

    var key = await window.crypto.subtle.digest(
        {
            name: "SHA-256",
        },
        new Uint8Array(secret)
    );

    console.log("secret");
    console.log(secret);
    console.log("key");
    console.log(key);
    return key;
}

async function encrypt(keyValue, data) {
    var key  = await window.crypto.subtle.importKey(
        "raw", keyValue,
        {   //this is the algorithm options
            name: "AES-CBC",
        },
        false, //whether the key is extractable (i.e. can be used in exportKey)
        ["encrypt", "decrypt"] //can be "encrypt", "decrypt", "wrapKey", or "unwrapKey"
    );

    var iv = window.crypto.getRandomValues(new Uint8Array(16));
    var encrypted = await window.crypto.subtle.encrypt(
        {
            name: "AES-CBC",
            //Don't re-use initialization vectors!
            //Always generate a new iv every time your encrypt!
            iv: iv,
        },
        key, //from generateKey or importKey above
        data //ArrayBuffer of data you want to encrypt
    );

    return [iv, encrypted];
}

async function decrypt(keyValue, iv, data) {
    var key  = await window.crypto.subtle.importKey(
        "raw", //can be "jwk" or "raw"
        keyValue,
        {   //this is the algorithm options
            name: "AES-CBC",
        },
        false, //whether the key is extractable (i.e. can be used in exportKey)
        ["encrypt", "decrypt"] //can be "encrypt", "decrypt", "wrapKey", or "unwrapKey"
    );

    var decrypted = await window.crypto.subtle.decrypt(
        {
            name: "AES-CBC",
            iv: iv,
        },
        key, //from generateKey or importKey above
        data //ArrayBuffer of data you want to encrypt
    );

    return decrypted;
}

function toHexString(byteArray) {
  return Array.prototype.map.call(byteArray, function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('');
}

function toByteArray(hexString) {
  var result = [];
  for (var i = 0; i < hexString.length; i += 2) {
    result.push(parseInt(hexString.substr(i, 2), 16));
  }
  return result;
}
