#!/usr/bin/env node

const rsaWrapper = require('./rsa-wrapper');
const aesWrapper = require('./aes-wrapper');
const uuidv4 = require('uuid/v4');

const serverAddress = 'ws://localhost:8001';

var WebSocketClient = require('websocket').client;

const listenMode = (process.argv.length >=4 && process.argv[3].trim() === '--listen');

const myName = process.argv[2].trim();

var client = new WebSocketClient();

var handshake = null;
var sharedKey = null;

let counter = 0;
let callsCount = 0;
let duplicates = 0;

var acks = [];
var recv_ids = [];

rsaWrapper.initLoadServerKeys(myName);

client.on('connectFailed', function (error) {
    console.log('Connect Error: ' + error.toString());
});

client.on('connect', function (connection) {
    console.log('WebSocket Client Connected');
    connection.on('error', function (error) {
        console.log("Connection Error: " + error.toString());
    });
    connection.on('close', function () {
        console.log('Connection Closed');
        handshake = null;
        sharedKey = null;
        setTimeout(() => {
            RetryConnect();
        }, 10);
    });
    connection.on('message', function (message) {
        if (message.type === 'utf8') {
            //console.log("Received: '" + message.utf8Data + "'");

            if (!handshake) {
                var question_enc = JSON.parse(message.utf8Data).question;
                var signature = JSON.parse(message.utf8Data).signature;

                var question = rsaWrapper.decrypt(rsaWrapper.bankPrivate, question_enc);

                const verified = rsaWrapper.verifySignature(rsaWrapper.serverPub, question, signature);

                if (!verified) {
                    console.log('Server not verified!');
                    process.exit(1);
                }

                question_enc = rsaWrapper.encrypt(rsaWrapper.serverPub, question);

                const my_signature = rsaWrapper.createSignature(rsaWrapper.bankPrivate, question);

                const msg = {
                    answer: question_enc,
                    signature: my_signature
                }

                handshake = true;
                connection.sendUTF(JSON.stringify(msg));
                return;
            }
            if (!sharedKey) {
                var key_enc = JSON.parse(message.utf8Data).key;
                var iv_enc = JSON.parse(message.utf8Data).iv;
                var signature_key = JSON.parse(message.utf8Data).signature_key;
                var signature_iv = JSON.parse(message.utf8Data).signature_iv;

                var key = rsaWrapper.decrypt(rsaWrapper.bankPrivate, key_enc);
                var iv = rsaWrapper.decrypt(rsaWrapper.bankPrivate, iv_enc);


                const verified_key = rsaWrapper.verifySignature(rsaWrapper.serverPub, key, signature_key);
                const verified_iv = rsaWrapper.verifySignature(rsaWrapper.serverPub, iv, signature_iv);


                if (!verified_key || !verified_iv) {
                    console.log('Server not verified!');
                    process.exit(1);
                }
                else {
                    console.log('server verified successfully.');
                }

                console.log('key : ' + key);
                console.log('iv : ' + iv);

                sharedKey = {
                    key: key,
                    iv: iv
                }
            }
            else {
                var msg = JSON.parse(message.utf8Data);
                //console.log(msg);
                if (msg.type === 'message')
                {
                    if (recv_ids.indexOf(msg.id) > -1)
                    {
                        //already got it, do nothing;
                        duplicates++;
                        console.log({duplicates});
                    }
                    else
                    {
                        recv_ids.push(msg.id);

                        counter++;
                        var msg_dec = aesWrapper.decrypt(sharedKey.key, sharedKey.iv, msg.msg);
                        // if (counter % 1000 == 0)
                        {
                            console.log(`${counter} - received decrypted : ${msg.id} : ${msg_dec}`);
                            const msg_enc = aesWrapper.encrypt(sharedKey.key, sharedKey.iv, JSON.stringify({type : 'ack' , payload : msg.id }));
                            connection.sendUTF(msg_enc);
                        }
                    }
                 }
                 else if (msg.type === 'ack')
                 {
                     acks.push(msg.payload);
                     console.log(msg);
                 }
            }

        }
    });

    function sayMyName() {
        if (connection.connected) {
            connection.sendUTF(myName);
        }
    }

    function RetryConnect() {
        if (!exitSignalReceived)
        {
            console.log("retrying to connect to server....");
            client.connect(serverAddress);
        }
    }



    function sendNumber() {
        if (connection.connected) {
            var number = Math.round(Math.random() * 0xFFFFFF);
            connection.sendUTF(number.toString());
            setTimeout(sendNumber, 1);
        }
    }

  
    const maxCalls = 200;
    function sendTestMessasges() {
        if (connection.connected && sharedKey) {

            callsCount++;
            if (callsCount > maxCalls)
                return;
    
            var id = uuidv4();
            var message = {
                id : id,
                type : 'message',
                receiver : 'MELI',
                payload : `Hello World ${callsCount}`
            }
            var msg = aesWrapper.encrypt(sharedKey.key, sharedKey.iv, JSON.stringify(message));
            connection.sendUTF(msg);

            var count = 0;
            var timer = setInterval(() => { 
                count++; 
                if (acks.indexOf(id) > -1)
                {
                    clearInterval(timer); 
                }
                else if (count >= 10) { 
                    clearInterval(timer); 
                    console.log(`could not send message to core :msg: ${msg}`);
                } 
                else
                {
                    if (connection.connected && sharedKey)
                    {
                        msg = aesWrapper.encrypt(sharedKey.key, sharedKey.iv, JSON.stringify(message));
                        connection.sendUTF(msg);
                        console.log(callsCount + '-retrying sending : ' + JSON.stringify(message));
                    }
                }
            }, 2000);  

            console.log(callsCount + '-sending : ' + JSON.stringify(message));
            setTimeout(sendTestMessasges, 50);
        }
    }

    sayMyName();

    if (listenMode)
    {
        console.log("client is up and ready in listen mode");
    }
    else
    {
        setTimeout(() => {
            sendTestMessasges()
        }, 1000);
    }

});

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
    client.socket.end();
    setTimeout(() => {
        process.exit(0);
    }, 2000); 
}


client.connect(serverAddress);