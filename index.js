#!/usr/bin/env node

const rsaWrapper = require('./rsa-wrapper');
const aesWrapper = require('./aes-wrapper');

const serverAddress = 'ws://localhost:8001';

var WebSocketClient = require('websocket').client;

const myName = process.argv[2].trim();

var client = new WebSocketClient();

var handshake = null;
var sharedKey = null;

let counter = 0;

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
        //RetryConnect();
    });
    connection.on('message', function (message) {
        if (message.type === 'utf8') {
           // console.log("Received: '" + message.utf8Data + "'");

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
                counter++;
                var msg_dec = aesWrapper.decrypt(sharedKey.key, sharedKey.iv, message.utf8Data);
                if (counter % 1000 == 0)
                {
                    console.log(`${counter} - received decrypted : ${msg_dec}`);
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
        console.log("retrying to connect to server....");
        setTimeout(() => {
            client.connect(serverAddress);
        }, 1000);
    }



    function sendNumber() {
        if (connection.connected) {
            var number = Math.round(Math.random() * 0xFFFFFF);
            connection.sendUTF(number.toString());
            setTimeout(sendNumber, 1000);
        }
    }

    function sendHelloWorld() {
        if (connection.connected) {
            var number = Math.round(Math.random() * 0xFFFFFF);
            var message = 'Hello World ' + number;
            const msg = aesWrapper.encrypt(sharedKey.key, sharedKey.iv, message);
            connection.sendUTF(msg);
            console.log('sending : ' + msg);
            setTimeout(sendHelloWorld, 100);
        }
    }

    sayMyName();

    // setTimeout(() => {
    //     sendHelloWorld()
    // }, 2000);

});

client.connect(serverAddress);