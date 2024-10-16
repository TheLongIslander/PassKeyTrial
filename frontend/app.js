function base64ToUint8Array(base64url) {
    // Convert base64url to base64 by replacing characters and adding padding
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const paddedBase64 = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');

    const binaryString = window.atob(paddedBase64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

function bufferToBase64UrlEncoded(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

document.addEventListener('DOMContentLoaded', () => {
    const usernameInput = document.getElementById('username');
    const registerBtn = document.getElementById('registerBtn');
    const loginBtn = document.getElementById('loginBtn');
    const messageDiv = document.getElementById('message'); // New element to display messages

    // Function to display messages
    function displayMessage(message, success = true) {
        messageDiv.textContent = message;
        messageDiv.style.color = success ? 'green' : 'red';
    }

    registerBtn.addEventListener('click', async () => {
        const username = usernameInput.value;

        const response = await fetch('http://localhost:3000/register/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        const data = await response.json();
        console.log('Register Start Data:', data);

        const publicKey = {
            ...data,
            challenge: base64ToUint8Array(data.challenge),  // Decode base64url challenge into Uint8Array
            user: {
                ...data.user,
                id: base64ToUint8Array(btoa(username)),  // Convert username to Uint8Array
            },
        };

        let credential;
        try {
            credential = await navigator.credentials.create({ publicKey });
            console.log('Credential Created:', credential);
        } catch (err) {
            console.error('Error during credential creation:', err);
            displayMessage('Error during credential creation. Try again.', false);
            return;
        }

        const credentialData = {
            id: bufferToBase64UrlEncoded(credential.rawId),
            rawId: bufferToBase64UrlEncoded(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: bufferToBase64UrlEncoded(credential.response.attestationObject),
                clientDataJSON: bufferToBase64UrlEncoded(credential.response.clientDataJSON)
            }
        };

        const finishResponse = await fetch('http://localhost:3000/register/finish', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                data: credentialData
            })
        });

        const finishData = await finishResponse.json();
        console.log('Register Finish Data:', finishData);

        if (finishData.res) {
            displayMessage('Registration successful!');
        } else {
            displayMessage('Registration failed. Try again.', false);
        }
    });

    // Add login functionality
    loginBtn.addEventListener('click', async () => {
        const username = usernameInput.value;

        // Step 1: Start the login process by getting a challenge from the server
        const response = await fetch('http://localhost:3000/login/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        const data = await response.json();
        console.log('Login Start Data:', data);

        const publicKeyCredentialRequestOptions = {
            challenge: base64ToUint8Array(data.challenge),  // Decode base64url challenge into Uint8Array
            rpId: data.rpId,
            allowCredentials: data.allowCredentials.map(cred => ({
                id: base64ToUint8Array(cred.id),
                type: cred.type,
                transports: cred.transports
            })),
            userVerification: data.userVerification,
        };

        // Step 2: Use WebAuthn API to get credentials for login
        let assertion;
        try {
            assertion = await navigator.credentials.get({ publicKey: publicKeyCredentialRequestOptions });
            console.log('Assertion Created:', assertion);
        } catch (err) {
            console.error('Error during assertion creation:', err);
            displayMessage('Error during login. Try again.', false);
            return;
        }

        // Step 3: Extract data to send back to the server for verification
        const assertionData = {
            id: assertion.id,
            rawId: bufferToBase64UrlEncoded(assertion.rawId),
            type: assertion.type,
            response: {
                authenticatorData: bufferToBase64UrlEncoded(assertion.response.authenticatorData),
                clientDataJSON: bufferToBase64UrlEncoded(assertion.response.clientDataJSON),
                signature: bufferToBase64UrlEncoded(assertion.response.signature),
                userHandle: assertion.response.userHandle ? bufferToBase64UrlEncoded(assertion.response.userHandle) : null
            }
        };

        // Step 4: Send the login assertion data back to the server
        const finishResponse = await fetch('http://localhost:3000/login/finish', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                data: assertionData
            })
        });

        const finishData = await finishResponse.json();
        console.log('Login Finish Data:', finishData);

        if (finishData.res) {
            displayMessage('Login successful!');
        } else {
            displayMessage('Login failed. Try again.', false);
        }
    });
});
