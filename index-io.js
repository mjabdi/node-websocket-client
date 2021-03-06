const io = require('socket.io-client');
const rsaWrapper = require('./rsa-wrapper');
const aesWrapper = require('./aes-wrapper');
const uuidv4 = require('uuid/v4');

let sharedKey = null;

const myName = process.argv[2].trim();
rsaWrapper.initLoadServerKeys(myName);

let error;

const socket = io('http://localhost:8001',{
    autoConnect: false,
    transports: [ 'websocket' ]
  });

socket.on('connect', () =>
{
    console.log('socket connected');
    socket.emit('authentication', {
        bank: myName,
      });
});

socket.on('unauthorized', (reason) => {
    console.log('Unauthorized:', reason);
    error = reason.message;
    socket.disconnect();
});


socket.on('authorized', (data) => {
    var key_enc = data.key;
    var iv_enc = data.iv;
    var signature_key = data.signature_key;
    var signature_iv = data.signature_iv;

    var key = rsaWrapper.decrypt(rsaWrapper.bankPrivate, key_enc);
    var iv = rsaWrapper.decrypt(rsaWrapper.bankPrivate, iv_enc);

    const verified_key = rsaWrapper.verifySignature(rsaWrapper.serverPub, key, signature_key);
    const verified_iv = rsaWrapper.verifySignature(rsaWrapper.serverPub, iv, signature_iv);

    if (!verified_key || !verified_iv) {
        console.log('Server not verified!');
        process.exit(1);
    }

    console.log('key : ' + key);
    console.log('iv : ' + iv);

    sharedKey = {
        key: key,
        iv: iv
    }

    authorized = true;
    if (myName === 'MELI')
    {
        setTimeout(() => {
            sendTestMessages();
        }, 1000);    
    }
});

socket.on('event', (data) =>
{
    console.log(`event received : ${data}`);
});

socket.on('handshake', (data) =>
{
    var question = rsaWrapper.decrypt(rsaWrapper.bankPrivate, data.question);
    const verified = rsaWrapper.verifySignature(rsaWrapper.serverPub, question, data.signature);

    if (!verified) {
        console.log('Server not verified!');
        process.exit(1);
    }

    const question_enc = rsaWrapper.encrypt(rsaWrapper.serverPub, question);
    const my_signature = rsaWrapper.createSignature(rsaWrapper.bankPrivate, question);

    socket.emit('handshake' , { answer: question_enc, signature: my_signature });
});

let receivedCount = 0;
socket.on('message', (data) =>
{
    receivedCount++;
    const msg_dec = aesWrapper.decrypt(sharedKey.key, sharedKey.iv, data);
    console.log(`${receivedCount} - message received : ${msg_dec}`);
});

socket.on('disconnect', (reason) =>
{
    console.log(`Disconnected: ${error || reason}`);
    authorized = false
    if (!exitSignalReceived)
    {
        console.log('trying to reconnect...');
        socket.open();       
        if (!socket.connected)
        {
            var timer = setInterval(() => { 

                if (!socket.connected)
                {
                    console.log('trying to reconnect...');
                    socket.open();
                }
                else
                {
                    clearInterval(timer);
                }
            }, 2000);  
        }
    }
});

let counter = 0;
let authorized = false;
function sendTestMessages()
{
    if (exitSignalReceived || !authorized)
        return;
        
    counter++;
    const msg =  {receiver: 'BSIR', payload: `Test Message ${counter}`};
    if (socket.connected)
    {
        const msg_enc = aesWrapper.encrypt(sharedKey.key, sharedKey.iv, JSON.stringify(msg));
        socket.emit('message' , msg_enc, function(data) {
            const msg_dec = aesWrapper.decrypt(sharedKey.key, sharedKey.iv, data);
            console.log(`message sent : ${msg_dec}`);          
        });
    }

    setTimeout(() => {
        sendTestMessages();
    }, 1000);
}

let exitSignalReceived = false;
process.on('SIGINT', () => {
    if (!exitSignalReceived) {
        exitSignalReceived = true;
        console.log('SIGTERM signal received.');
        shutdown();
    }
    else {
        console.log('application is shutting down. please wait...');
    }
});

function shutdown()
{
    console.log('application is shutting down...');
    setTimeout(() => {
        process.exit(0);
    }, 3000); 
}

socket.open();
   