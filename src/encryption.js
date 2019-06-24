

async function run() {
    ////////////////////////////////////////// Setup Keys //////////////////////////////////////////
    var sender = await window.crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
        },
        true, //whether the key is extractable (i.e. can be used in exportKey)
        ["sign", "verify"]
    );
    var receiver1 = await window.crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
        },
        true, //whether the key is extractable (i.e. can be used in exportKey)
        ["sign", "verify"]
    );
    var receiver2 = await window.crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
        },
        true, //whether the key is extractable (i.e. can be used in exportKey)
        ["sign", "verify"]
    );

    document.getElementById('sender_priv').innerHTML = await privateText(sender.privateKey);
    document.getElementById('sender_pub_x').innerHTML = await publicXText(sender.publicKey);
    document.getElementById('sender_pub_y').innerHTML = await publicYText(sender.publicKey);

    document.getElementById('receiver1_priv').innerHTML = await privateText(receiver1.privateKey);
    document.getElementById('receiver1_pub_x').innerHTML = await publicXText(receiver1.publicKey);
    document.getElementById('receiver1_pub_y').innerHTML = await publicYText(receiver1.publicKey);

    document.getElementById('receiver2_priv').innerHTML = await privateText(receiver2.privateKey);
    document.getElementById('receiver2_pub_x').innerHTML = await publicXText(receiver2.publicKey);
    document.getElementById('receiver2_pub_y').innerHTML = await publicYText(receiver2.publicKey);

    //////////////////////////////////////// Derive Secrets ////////////////////////////////////////
    var sender_secret1 = await secret(sender.privateKey, receiver1.publicKey);
    var sender_key1 = await window.crypto.subtle.digest(
        {
            name: "SHA-256",
        },
        new Uint8Array(sender_secret1)
    );
    document.getElementById('sender_secret1').innerHTML = window.btoa(String.fromCharCode(...new Uint8Array(sender_secret1)));

    var sender_secret2 = await secret(sender.privateKey, receiver2.publicKey);
    var sender_key2 = await window.crypto.subtle.digest(
        {
            name: "SHA-256",
        },
        new Uint8Array(sender_secret2)
    );
    document.getElementById('sender_secret2').innerHTML = window.btoa(String.fromCharCode(...new Uint8Array(sender_secret2)));

    var receiver1_secret = await secret(receiver1.privateKey, sender.publicKey);
    var receiver1_key = await window.crypto.subtle.digest(
        {
            name: "SHA-256",
        },
        new Uint8Array(receiver1_secret)
    );
    document.getElementById('receiver1_secret').innerHTML = window.btoa(String.fromCharCode(...new Uint8Array(receiver1_secret)));

    var receiver2_secret = await secret(receiver2.privateKey, sender.publicKey);
    var receiver2_key = await window.crypto.subtle.digest(
        {
            name: "SHA-256",
        },
        new Uint8Array(receiver2_secret)
    );
    document.getElementById('receiver2_secret').innerHTML = window.btoa(String.fromCharCode(...new Uint8Array(receiver2_secret)));

    /////////////////////////////////////// Encrypt Master Key /////////////////////////////////////
    var master_secret = window.crypto.getRandomValues(new Uint8Array(32));
    var master_key = await window.crypto.subtle.digest(
        {
            name: "SHA-256",
        },
        new Uint8Array(master_secret)
    );
    document.getElementById('master_key').innerHTML = window.btoa(String.fromCharCode(...new Uint8Array(master_key)));

    /////////////////////////////////////// Decrypt Master Key /////////////////////////////////////
    var encrypted1 = await encrypt(sender_key1, master_key);
    var iv1 = encrypted1[0];
    var encrypted_key1 = encrypted1[1];
    var decrypted_key1 = await decrypt(receiver1_key, iv1, encrypted_key1);
    document.getElementById('master_key1').innerHTML = window.btoa(String.fromCharCode(...new Uint8Array(decrypted_key1)));

    var encrypted2 = await encrypt(sender_key2, master_key);
    var iv2 = encrypted2[0];
    var encrypted_key2 = encrypted2[1];
    var decrypted_key2 = await decrypt(receiver2_key, iv2, encrypted_key2);
    document.getElementById('master_key2').innerHTML = window.btoa(String.fromCharCode(...new Uint8Array(decrypted_key2)));

    ///////////////////////////////////////// Encrypt Message //////////////////////////////////////
    var message = "Shh. Dont let them see this.";
    document.getElementById('sender_message').innerHTML = message;

    var message_data = new TextEncoder().encode(message);
    var encrypted_message = await encrypt(master_key, message_data);
    var message_iv = encrypted_message[0];
    var encrypted_message = encrypted_message[1];

    var decrypted_message1 = await decrypt(decrypted_key1, message_iv, encrypted_message);
    document.getElementById('receiver1_message').innerHTML = new TextDecoder("utf-8").decode(decrypted_message1);

    var decrypted_message2 = await decrypt(decrypted_key2, message_iv, encrypted_message);
    document.getElementById('receiver2_message').innerHTML = new TextDecoder("utf-8").decode(decrypted_message2);
}

async function privateText(key) {
    var data = await window.crypto.subtle.exportKey("jwk", key);
    return data.d;
}

async function publicXText(key) {
    var data = await window.crypto.subtle.exportKey("jwk", key);
    return data.x;
}

async function publicYText(key) {
    var data = await window.crypto.subtle.exportKey("jwk", key);
    return data.y;
}

async function secret(privateKey, publicKey) {

    // Convert keys from ECDSA to ECDH
    var privdata = await window.crypto.subtle.exportKey("pkcs8", privateKey);
    var privkey = await window.crypto.subtle.importKey(
        "pkcs8", privdata,
        {   //these are the algorithm options
            name: "ECDH",
            namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
        },
        false, //whether the key is extractable (i.e. can be used in exportKey)
        ["deriveKey", "deriveBits"] //"deriveKey" and/or "deriveBits" for private keys only (just put an empty list if importing a public key)
    )
    // console.log("privkey");
    // console.log(privkey);

    var pubdata = await window.crypto.subtle.exportKey("spki", publicKey);
    var pubkey = await window.crypto.subtle.importKey(
        "spki", pubdata,
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

    // console.log("secret");
    // console.log(secret);
    return secret;
}

async function encrypt(keyValue, data) {
    var key  = await window.crypto.subtle.importKey(
        "raw", //can be "jwk" or "raw"
        keyValue,
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
