const aesWrapper = require('./aes-wrapper');


const key = aesWrapper.generateKey();
const iv = aesWrapper.generateIv();

const message = 'Hello World!';

const encryptedMessage = aesWrapper.encrypt(key,iv,message);
const decryptedMessage = aesWrapper.decrypt(key,iv, encryptedMessage.replace(12,'H'));

console.log(encryptedMessage);
console.log(decryptedMessage);
