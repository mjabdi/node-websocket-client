const crypto = require('crypto');

const aesWrapper = {};

// get list of supportable encryption algorithms
aesWrapper.getAlgorithmList = () => {
    console.log(crypto.getCiphers());
};

aesWrapper.generateKey = () => {
    return crypto.randomBytes(32);
};

aesWrapper.generateIv = () => {
    return crypto.randomBytes(16);
};

// separate initialization vector from message
aesWrapper.separateVectorFromData = (data) =>  {
    console.log(data);
    console.log('data');
    var iv = data.slice(-24);
    var message = data.substring(0, data.length - 24)

    return{
        iv: iv,
        message: message
    };
}

aesWrapper.encrypt = (key, iv, text) => {
    let encrypted = '';
    let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key,'base64'), Buffer.from(iv,'base64'));
    encrypted += cipher.update(Buffer.from(text), 'utf8', 'base64');
    encrypted += cipher.final('base64');

    return encrypted;
};

aesWrapper.decrypt = (key, iv , text) => {
    let dec = '';
    // let data = aesWrapper.separateVectorFromData(text);
    let cipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key,'base64'), Buffer.from(iv,'base64'));
    dec += cipher.update(Buffer.from(text, 'base64'), 'base64', 'utf8');
    dec += cipher.final('utf8');

    return dec;
};

// add initialization vector to message
aesWrapper.addIvToBody = (iv, encryptedBase64) => {
    encryptedBase64 += iv.toString('base64');
    console.log(iv.toString('base64'));

    return encryptedBase64;
};

aesWrapper.createAesMessage = (aesKey, message) => {
    let aesIv = aesWrapper.generateIv();
    let encryptedMessage = aesWrapper.encrypt(aesKey, aesIv, message);
    encryptedMessage = aesWrapper.addIvToBody(aesIv, encryptedMessage);

    return encryptedMessage;
};

module.exports = aesWrapper;