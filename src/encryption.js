

async function generateAll() {
    await generateSender();
    await generateReceiver1();
    await generateReceiver2();
    await generateMaster();
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
        key_data
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
    document.getElementById('sender_receiver1_ecdh').innerHTML = toHexString(new Uint8Array(key));

    var master_key = toByteArray(document.getElementById('master_key').innerHTML);

    var encrypted = await encrypt(key, master_key);
    document.getElementById('receiver1_IV').innerHTML = toHexString(encrypted[0]);
    document.getElementById('receiver1_encrypted_key').innerHTML = toHexString(new Uint8Array(encrypted[1]));
}

async function encryptReceiver2() {
    var senderPriv = bsv.HDPrivateKey.fromString(document.getElementById('sender_priv').value).privateKey;
    var receiver2Pub = bsv.HDPublicKey.fromString(document.getElementById('receiver2_pub').value).publicKey;
    var key = await dhKey(senderPriv, receiver2Pub);
    document.getElementById('sender_receiver2_ecdh').innerHTML = toHexString(new Uint8Array(key));

    var master_key = toByteArray(document.getElementById('master_key').innerHTML);

    var encrypted = await encrypt(key, master_key);
    document.getElementById('receiver2_IV').innerHTML = toHexString(encrypted[0]);
    document.getElementById('receiver2_encrypted_key').innerHTML = toHexString(new Uint8Array(encrypted[1]));
}

async function decryptReceiver1() {
    var senderPub = bsv.HDPublicKey.fromHDPrivateKey(bsv.HDPrivateKey.fromString(document.getElementById('sender_priv').value)).publicKey;
    var receiver1Priv = bsv.HDPrivateKey.fromString(document.getElementById('receiver1_priv').value).privateKey;
    var key = await dhKey(receiver1Priv, senderPub);
    document.getElementById('receiver1_sender_ecdh').innerHTML = toHexString(key);

    var iv_master_key = toByteArray(document.getElementById('receiver1_IV').innerHTML);
    var encrypted_master_key = toByteArray(document.getElementById('receiver1_encrypted_key').innerHTML);
    var decrypted_master_key = new Uint8Array(await decrypt(key, iv_master_key, encrypted_master_key))
    document.getElementById('receiver1_key').innerHTML = toHexString(decrypted_master_key);

    var iv_message = toByteArray(document.getElementById('message_iv').innerHTML);
    var encrypted_message = toByteArray(document.getElementById('encrypted_message').innerHTML);
    console.log(decrypted_master_key)
    console.log(iv_message)
    console.log(encrypted_message)
    var decrypted_message = await decrypt(decrypted_master_key, iv_message, encrypted_message)
    console.log(new TextDecoder("utf-8").decode(decrypted_message))
    // document.getElementById('receiver1_message').innerHTML = new TextDecoder("utf-8").decode(decrypted_message);
}

async function decryptReceiver2() {
    var senderPub = bsv.HDPublicKey.fromHDPrivateKey(bsv.HDPublicKey.fromString(document.getElementById('sender_priv').value)).publicKey;
    var receiver2Priv = bsv.HDPrivateKey.fromString(document.getElementById('receiver2_priv').value).privateKey;
    var key = await dhKey(receiver2Priv, senderPub);
    document.getElementById('receiver2_sender_ecdh').innerHTML = toHexString(key);

    var iv_master_key = toByteArray(document.getElementById('receiver2_IV').innerHTML);
    var encrypted_master_key = toByteArray(document.getElementById('receiver2_encrypted_key').innerHTML);
    var decrypted_master_key = await decrypt(key, iv_master_key, encrypted_master_key)
    document.getElementById('receiver2_key').innerHTML = toHexString(new Uint8Array(decrypted_master_key));


}

async function dhKey(privateKey, publicKey) {

    dh = publicKey.point.mul(privateKey.toBigNumber())

    var key = await window.crypto.subtle.digest(
        {
            name: "SHA-256",
        },
        new Uint8Array(dh.getX().toBuffer())
    );

    return new Uint8Array(key);
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
  return new Uint8Array(result);
}
