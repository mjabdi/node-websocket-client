const path = require('path');
const rsaWrapper = {};
const fs = require('fs');
const NodeRSA = require('node-rsa');
const crypto = require('crypto');

// load keys from file
rsaWrapper.initLoadServerKeys = () => {

    let privateKeyPath = path.resolve(__dirname, './keys' ,  'MELI.private.pem');
    let publicKeyPath = path.resolve(__dirname, './keys' , 'MELI.public.pem');

    rsaWrapper.bankPub = fs.readFileSync(publicKeyPath);
    rsaWrapper.bankPrivate = fs.readFileSync(privateKeyPath);

    publicKeyPath = path.resolve(__dirname, './keys' , 'server.public.pem');
    rsaWrapper.serverPub = fs.readFileSync(publicKeyPath);
};


rsaWrapper.encrypt = (publicKey, message) => {
    let enc = crypto.publicEncrypt({
        key: publicKey,
        padding: crypto.RSA_PKCS1_OAEP_PADDING
    }, Buffer.from(message));

    return enc.toString('base64');
};

rsaWrapper.decrypt = (privateKey, message) => {
    try{
        let enc = crypto.privateDecrypt({
            key: privateKey,
            padding: crypto.RSA_PKCS1_OAEP_PADDING
        }, Buffer.from(message, 'base64'));

        return enc.toString();
    }
    catch(err)
    {
        throw new Error('Invalid Certificate');
    }
};

rsaWrapper.createSignature = (privateKey , message) =>
{
    const signer = crypto.createSign('sha256');
    signer.update(message);
    signer.end();

    const signature = signer.sign(privateKey);
    return signature.toString('base64');
}

rsaWrapper.verifySignature = (publicKey , message, signature) =>
{
    const verifier = crypto.createVerify('sha256');
    verifier.update(message);
    verifier.end();
    const verified = verifier.verify(publicKey, Buffer.from(signature, 'base64'));
    return verified;
}





module.exports = rsaWrapper;