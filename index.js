const express = require('express');
const crypto = require('crypto');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cors = require('cors');
require('dotenv').config();
const SimpleWebAuthnServer = require('@simplewebauthn/server');
const base64url = require('base64url');
const app = express();

app.use(cors({ origin: '*' }));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

const db = new sqlite3.Database('./users.db');

// Create users table if it doesn't exist
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            credentialID TEXT,
            publicKey BLOB,
            counter INTEGER,
            registered BOOLEAN
        );
    `, (err) => {
        if (err) {
            console.error("Error creating users table:", err.message);
        } else {
            console.log("Users table created successfully or already exists.");
        }
    });
});

let challenges = {};
const rpId = 'localhost';
const expectedOrigin = ['http://localhost:3000'];

app.listen(process.env.PORT || 3000, err => {
    if (err) throw err;
    console.log('Server started on port', process.env.PORT || 3000);
});

app.use(express.static(path.join(__dirname, 'frontend')));

app.post('/register/start', (req, res) => {
    let username = req.body.username;
    let challenge = getNewChallenge();  // Generate a new challenge
    challenges[username] = challenge;   // Store raw challenge without conversion
    const pubKey = {
        challenge: base64url.encode(challenge),  // Encode challenge to base64url
        rp: {id: rpId, name: 'webauthn-app'},
        user: {id: username, name: username, displayName: username},
        pubKeyCredParams: [
            {type: 'public-key', alg: -7},
            {type: 'public-key', alg: -257},
        ],
        authenticatorSelection: {
            authenticatorAttachment: 'platform',
            userVerification: 'required',
            residentKey: 'preferred',
            requireResidentKey: false,
        }
    };
    res.json(pubKey);
});

app.post('/register/finish', async (req, res) => {
    const username = req.body.username;
    let expectedChallenge = challenges[username];  // Retrieve raw challenge
    let verification;

    try {
        verification = await SimpleWebAuthnServer.verifyRegistrationResponse({
            response: req.body.data,
            expectedChallenge: base64url.encode(expectedChallenge),  // Encode challenge before comparing
            expectedOrigin: expectedOrigin,
        });
    } catch (error) {
        console.error(error);
        return res.status(400).send({ error: error.message });
    }

    const { verified, registrationInfo } = verification;
    if (verified) {
        const { credentialID, counter, credentialPublicKey } = registrationInfo;

        // Check if the user already exists in the database
        db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, row) => {
            if (err) {
                console.error(err);
                return res.status(500).send({ error: 'Failed to query user information' });
            }
            if (row) {
                return res.status(400).send({ error: 'User already registered' });
            } else {
                // Insert the new user into the database (make sure all column names are correct)
                db.run(
                    `INSERT INTO users (username, credentialID, publicKey, counter, registered) 
                    VALUES (?, ?, ?, ?, ?)`,
                    [
                        username,
                        credentialID.toString('base64'),  // Store credentialID as base64
                        credentialPublicKey,  // Store credentialPublicKey as a binary BLOB
                        counter,
                        true
                    ],
                    function (err) {
                        if (err) {
                            console.error("Error during user insertion:", err.message);
                            return res.status(500).send({ error: 'Failed to store user information' });
                        }
                        return res.status(200).send({ res: true });
                    }
                );
            }
        });
    } else {
        res.status(500).send({ res: false });
    }
});

app.post('/login/start', (req, res) => {
    const username = req.body.username;

    // Retrieve user info from SQLite
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, row) => {
        if (err) {
            console.error(err);
            return res.status(500).send(false);
        }
        if (!row) {
            return res.status(404).send(false);
        }

        let challenge = getNewChallenge();
        challenges[username] = challenge;

        res.json({
            challenge: base64url.encode(challenge),
            rpId,
            allowCredentials: [{
                type: 'public-key',
                id: row.credentialID,  // Stored as base64
                transports: ['internal']
            }],
            userVerification: 'preferred'
        });
    });
});

app.post('/login/finish', async (req, res) => {
    const username = req.body.username;

    // Retrieve user info from SQLite
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, row) => {
        if (err) {
            console.error(err);
            return res.status(500).send({ error: 'Server error' });
        }
        if (!row) {
            return res.status(404).send({ error: 'User not found' });
        }

        let expectedChallenge = challenges[username];
        let verification;
        try {
            // Properly decode the stored credentialPublicKey (BLOB) and credentialID (base64)
            verification = await SimpleWebAuthnServer.verifyAuthenticationResponse({
                expectedChallenge: base64url.encode(expectedChallenge),
                response: req.body.data,
                authenticator: {
                    credentialPublicKey: row.publicKey,  // Use binary BLOB directly
                    credentialID: Buffer.from(row.credentialID, 'base64'),  // Convert credentialID from base64
                    counter: row.counter
                },
                expectedRPID: rpId,
                expectedOrigin,
                requireUserVerification: false
            });
        } catch (error) {
            console.error(error);
            return res.status(400).send({ error: error.message });
        }

        const { verified, authenticationInfo } = verification;
        if (verified) {
            // Update the counter in the database
            db.run(`UPDATE users SET counter = ? WHERE username = ?`, [authenticationInfo.newCounter, username], (err) => {
                if (err) {
                    console.error(err);
                    return res.status(500).send({ error: 'Failed to update counter' });
                }
                return res.status(200).send({ res: verified });
            });
        } else {
            res.status(400).send({ res: false });
        }
    });
});

function getNewChallenge() {
    return crypto.randomBytes(32);  // Generate a secure 32-byte challenge
}
