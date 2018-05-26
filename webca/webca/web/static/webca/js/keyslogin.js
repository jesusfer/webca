"use strict";

// https://docs.djangoproject.com/en/2.0/ref/csrf/
function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}
function csrfSafeMethod(method) {
    // these HTTP methods do not require CSRF protection
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}

// Get Django's CSRF token so that Ajax POSTs don't fail
$.ajaxSetup({
    beforeSend: function(xhr, settings) {
        if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
            xhr.setRequestHeader("X-CSRFToken", getCookie('csrftoken'));
        }
    }
});

function output(message) {
    if (console) {
        console.log(message);
    }
}

// Write to the console and the textbox in the keys setup page
function userMessage(message) {
    output(message);
    try {
        document.getElementById('user_message').innerText = message;
    }
    catch (error) {}
}

function disableButtons() {
    try {
        document.getElementById('create_button').disabled = true;
        document.getElementById('remove_button').disabled = true;
    }
    catch (error) {}
}

function enableButtons() {
    try {
        document.getElementById('create_button').disabled = false;
        document.getElementById('remove_button').disabled = false;
    }
    catch (error) {}
}

function clearPassphrase() {
    document.getElementById('id_passphrase').value = '';
    document.getElementById('create_button').style.display = 'inline-block';
    document.getElementById('passphrase').style.display = 'none';
}

function cb_errorDB(event) {
    output("Error using IndexedDB: " + event);
    output(event);
}

const dbVersion = 1;

function cb_prepareDB(event) {
    // onupgradeneeded is only implemented in recent browsers   
    output('DB Upgrade needed');
    var db = event.target.result;
    switch(event.oldVersion) {
        case 0:
            var objectStore = db.createObjectStore("keys", {
                keyPath: "email"
            });
            objectStore.createIndex("email", "email", {
                unique: true
            });
    }
}

var hasTextEncoder = true;

// Check that the browser meets some minimum requirements
function precheck() {
    if (!window.indexedDB) {
        userMessage("Your browser doesn't support a stable version of IndexedDB.");
        disableButtons();
        return false;
    }
    if (window.msCrypto) {
        userMessage("Your browser doesn't support a recent version of WebCrypto.");
        disableButtons();
        return false;
    }
    try {
        new TextEncoder();
    }
    catch (error) {
        hasTextEncoder = false;
        // Create this just so Edge can sign the authentication message
        window.TextEncoder = class TextEncoder {
            constructor(encoding) {}
            encode(str){
                var utf8 = unescape(encodeURIComponent(str));
                var result = new Uint8Array(utf8.length);
                for (var i = 0; i < utf8.length; i++) {
                    result[i] = utf8.charCodeAt(i);
                }
                return result;
            }
        }
    }
    return true;
}

// Look for installed keys in the browser
function cb_findKeys(event) {
    const db = event.target.result;
    db.onerror = event => {
        output("Database error (" + event.target.errorCode + ") " + event.target.error);
        userMessage("Couldn't open the browser database. Did you grant permissions?");
    };
    var keys = [];
    const store = db.transaction(["keys"]).objectStore("keys");
    store.onerror = event => {
        output('Error opening store');
    }
    store.openCursor().onsuccess = event => {
        var cursor = event.target.result;
        if (cursor) {
            keys.push(cursor.value);
            cursor.continue();
        }
        else if (keys.length > 0) {
            const key = keys.find(item => item.email === user_email)
            if (key) {
                userMessage('Yes');
                enableButtons();
            }
            else {
                userMessage('No');
                enableButtons();
            }
        }
        else {
            userMessage('No');
            enableButtons();
        }
    }
}

// Create the key pair and store it in IndexedDB
function cb_createKeys(event) {
    const db = event.target.result;
    db.onerror = event => {
        output("Database error (" + event.target.errorCode + ") " + event.target.error);
    };
    const store = db.transaction(["keys"], "readwrite").objectStore("keys");
    store.onerror = event =>  {
        output('Error opening store');
    }
    const crypto = new OpenCrypto();
    window.crypto.subtle.generateKey({
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-512" },
    }, true, ['sign'])
    .then(keyPair => {
        var creation = undefined;
        if (hasTextEncoder) {
            const passphrase = document.getElementById('id_passphrase').value;
            creation = Promise.all([
                crypto.cryptoPublicToPem(keyPair.publicKey).then(publicPem => { return publicPem }),
                crypto.encryptPrivateKey(keyPair.privateKey, passphrase).then(encryptedPrivateKey => { return encryptedPrivateKey }),
            ]);
        }
        else {
            creation = Promise.all([
                crypto.cryptoPublicToPem(keyPair.publicKey).then(publicPem => { return publicPem }),
                crypto.cryptoPrivateToPem(keyPair.privateKey).then(privatePem => { return privatePem }),
            ]);
        }
        creation.then(pemPair => {
            var keys = {
                email: user_email,
                public: pemPair[0],
                private: pemPair[1],
            }
            var rw_store = db.transaction(["keys"], 'readwrite').objectStore("keys");
            rw_store.put(keys).onsuccess = event => {
                output('Stored the certificate locally');
                $.post(post_url, {'key':keys.public})
                .done(function(data, status) {
                    output('Saved public key in the server');
                    findKeys();
                    clearPassphrase();
                })
                .fail(function(jqXHR, status) {
                    userMessage('Could not save the key in the server (' + jqXHR.statusText + ')')
                    clearPassphrase();
                });
            }
        })
    })
    .catch(error => {
        userMessage('Error creating keys: ' + error);
        clearPassphrase();
    })

}

// Remove the keys
// TODO: it may be interesting to notify the web application so that it can remove the public key too
function cb_removeKeys(event) {
    const db = event.target.result;
    db.onerror = event => {
        output("Database error (" + event.target.errorCode + ") " + event.target.error);
    };
    var keys = [];
    const store = db.transaction(["keys"], "readwrite").objectStore("keys");
    store.onerror = event => {
        output('Error opening store');
    }
    store.onsuccess = findKeys();
    store.delete(user_email);
}

// Call the login endpoint with the signed message so that the application can authenticate the user
// The message is the user's email. The server will validate the signed message because it's got
// the public key corresponding to the private key.
function doLogin(email, key) {
    const crypto = new OpenCrypto();
    var message = crypto.stringToArrayBuffer(email);
    return window.crypto.subtle.sign(
        {
            name: "RSASSA-PKCS1-v1_5",
            hash: { name: "SHA-512" },
        },
        key,
        message,
    )
    .catch(error => {
        output("Couldn't create the signed message");
    })
    .then(signed => {
        const crypto = new OpenCrypto();
        const base64 = crypto.arrayBufferToBase64(signed);
        return $.post('', {'email':email, 'signed':base64})
    }) // Login errors are handled in the parent function
}

var keyPair = undefined;
var choosenEmail = undefined;

// Prepare the login screen by checking the installed key pairs
// and showing the passphrase box if needed
function cb_login(event) {
    const db = event.target.result;
    db.onerror = event => {
        output("Database error (" + event.target.errorCode + ") " + event.target.error);
        window.location = code_login;
    };
    var keys = [];
    const store = db.transaction(["keys"]).objectStore("keys");
    store.onerror = event => {
        output('Error opening store');
        window.location = code_login;
    }
    store.openCursor().onsuccess = event => {
        var cursor = event.target.result;
        var found = false;
        if (cursor) {
            keys.push(cursor.value);
            cursor.continue();
        }
        else if (keys.length > 0) {
            if (keys.length > 1 && !choosenEmail) {
                $('#several_keys').show();
                $.each(keys, function (i, item) {
                    $('#several_keys select').append($('<option>', {
                        value: item.email,
                        text : item.email,
                    }));
                });
                return;
            }
            const crypto = new OpenCrypto();
            if (choosenEmail) {
                keyPair = keys.find(key => key.email == choosenEmail);
                $('#several_keys select').prop('disabled', true);
                $('#several_keys input').prop('disabled', true);
            }
            else {
                keyPair = keys[0];
            }
            if(hasTextEncoder) {
                if(keyPair.private.search('ENCRYPTED') >= 0) {
                    $('#passphrase').show();
                    return;
                }
            }
            else {
                crypto.pemPrivateToCrypto(keyPair.private, 'RSASSA-PKCS1-v1_5', ['sign'])
                .then(cryptoKey => {
                    return doLogin(keyPair.email, cryptoKey)
                    .then(url => {
                        window.location = url;
                    })
                    .catch(error => {
                        output('Could not login');
                        window.location = code_login;
                    })
                })
                .catch(error => {
                    output('Could not load the private key');
                    window.location = code_login;
                })
            }
        }
        else {
            window.location = code_login;
        }
    }
}

// If the selected key has a passphrase, then decrypt it and call the login function 
function decryptKeys() {
    $('.errorlist').hide();
    const crypto = new OpenCrypto();
    const passphrase = document.getElementById('id_passphrase').value;
    crypto.decryptPrivateKey(keyPair.private, passphrase, 'RSASSA-PKCS1-v1_5', ['sign'])
    .then(cryptoKey => {
        return doLogin(keyPair.email, cryptoKey)
        .then(url => {
            window.location = url;
        })
        .catch(error => {
            output('Could not login');
            window.location = code_login;
        })
    })
    .catch(error => {
        output('Could not decrypt the private key');
        $('#error').text('Could not decrypt the private key with the provided passphrase');
        $('.errorlist').show();
    })
}

// Check if there are keys installed in the browser.
function findKeys() {
    if (!precheck()) { return }
    var request = window.indexedDB.open("WebCA", dbVersion);
    request.onerror = cb_errorDB;
    request.onupgradeneeded = cb_prepareDB;
    request.onsuccess = cb_findKeys;
}

// The browser supports encrypting the passphrase, show the passphrase box
function getPassword() {
    if (hasTextEncoder) {
        document.getElementById('create_button').style.display = 'none';
        document.getElementById('passphrase').style.display = 'block';
    }
    else {
        setupKeys();
    }
}

// Create the keys and store them in the browser
function setupKeys() {
    if (!precheck()) { return }
    var request = window.indexedDB.open("WebCA", dbVersion);
    request.onerror = cb_errorDB;
    request.onupgradeneeded = cb_prepareDB;
    request.onsuccess = cb_createKeys;
}


// Remove the keys from this browser, but only for the logged in user
function removeKeys() {
    if (!precheck()) { return }
    var request = window.indexedDB.open("WebCA", dbVersion);
    request.onerror = cb_errorDB;
    request.onupgradeneeded = cb_prepareDB;
    request.onsuccess = cb_removeKeys;
}

// Start the login stuff
function login() {
    if (!precheck()) { 
        window.location = code_login;
        return;
    }
    var request = window.indexedDB.open("WebCA", dbVersion);
    request.onerror = cb_errorDB;
    request.onupgradeneeded = cb_prepareDB;
    request.onsuccess = cb_login;
}

// Start the process if there are several keys installed
function selectKey() {
    choosenEmail = $('#several_keys select')[0].selectedOptions[0].value;
    login();
}