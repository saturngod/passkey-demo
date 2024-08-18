const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { MongoClient } = require('mongodb');
const {
  generateRegistrationOptions,
  generateAuthenticationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const { isoUint8Array,decodeBase64URL } = require('@simplewebauthn/server/helpers');
const { Crypto } = require('@peculiar/webcrypto');

if (!Promise.any) {
  Promise.any = function(promises) {
    return new Promise((resolve, reject) => {
      let errors = [];
      let pending = promises.length;
      if (pending === 0) {
        return reject(new AggregateError([], 'All promises were rejected'));
      }
      promises.forEach((promise, index) => {
        Promise.resolve(promise)
          .then(resolve)
          .catch(error => {
            errors[index] = error;
            pending--;
            if (pending === 0) {
              reject(new AggregateError(errors, 'All promises were rejected'));
            }
          });
      });
    });
  };
}

const crypto = new Crypto();
global.crypto = crypto;

const app = express();
const port = 3001;

app.use(bodyParser.json());
app.use(cors());

const uri = "mongodb://localhost:27017/passkey-sample";


let usersCollection;
console.log("TRYING TO CONNECT TO MONGODB");

MongoClient.connect(uri).then((client) => {
  const db = client.db("passkey-sample");
  usersCollection = db.collection("users");
  console.log("Connected to MongoDB");

  app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
  });
});

// In-memory store for challenges (use a proper store in production)
const challenges = {};

const rpName = 'SimpleWebAuthn Example';
const rpID = 'localhost';
const origin = `http://${rpID}:3000`;

app.post('/register-options', async (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).send({ message: 'Username is required' });
  }

  try {
    const user = await usersCollection.findOne({ username });
    const userID = isoUint8Array.fromUTF8String(username);

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID,
      userName: username,
      attestationType: 'none',
      authenticatorSelection: {
        userVerification: 'preferred',
        residentKey: 'preferred',
      },
      excludeCredentials: user ? user.credentials.map(cred => ({
        id: cred.credentialID,
        transports: cred.transports,
      })) : [],
    }); 
    challenges[username] = options.challenge;

    console.log("Registration Options:", options);
    res.send(options);
  } catch (error) {
    console.error("Error generating registration options:", error);
    res.status(500).send({ message: 'Error generating registration options', error });
  }
});

app.post('/register', async (req, res) => {
  const { username, attestationResponse } = req.body;

  if (!username || !attestationResponse) {
    return res.status(400).send({ message: 'Username and attestation response are required' });
  }

  try {
    const expectedChallenge = challenges[username];

    const verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (verification.verified) {
      await usersCollection.updateOne(
        { username },
        {
          $push: {
            credentials: {
              credentialID: verification.registrationInfo.credentialID,
              publicKey: verification.registrationInfo.credentialPublicKey,
              counter: verification.registrationInfo.counter,
            },
          },
        },
        { upsert: true }
      );
      res.send({ verified: true });
    } else {
      res.status(400).send({ message: 'Verification failed' });
    }
  } catch (error) {
    console.error("Error verifying attestation:", error);
    res.status(500).send({ message: 'Error verifying attestation', error: error.message });
  }
});

app.post('/auth-options', async (req, res) => {
  const { username } = req.body;

  try {
    const user = await usersCollection.findOne({ username });

    if (!user) {
      return res.status(400).send({ message: 'User not found' });
    }

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: user.credentials.map(cred => ({
        id: cred.credentialID,
        transports: cred.transports,
      })),
      userVerification: 'preferred',
    });

    challenges[username] = options.challenge;

    console.log("Authentication Options:", options);
    res.send(options);
  } catch (error) {
    console.error("Error generating authentication options:", error);
    res.status(500).send({ message: 'Error generating authentication options', error });
  }
});

app.post('/authenticate', async (req, res) => {
  console.log(req.body);
  const { username, assertionResponse } = req.body;

  if (!username || !assertionResponse) {
    return res.status(400).send({ message: 'Username and assertion response are required' });
  }

  try {
    const user = await usersCollection.findOne({ username });

    if (!user) {
      return res.status(400).send({ message: 'User not found' });
    }

    const credential = user.credentials.find(cred => cred.credentialID === assertionResponse.id);

    if (!credential) {
      return res.status(400).send({ message: 'Credential not found' });
    }

    const expectedChallenge = challenges[username];

    console.log("Assertion Response:", JSON.stringify(assertionResponse, null, 2));
    console.log("Expected Challenge:", expectedChallenge);

    // Convert credentialPublicKey to Buffer if it's not already
    let credentialPublicKey = credential.publicKey.buffer;

    console.log("Credential Data:", JSON.stringify(credential, null, 2));
    console.log("Converted Public Key Buffer:", credentialPublicKey);

    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: Buffer.from(credential.credentialID, 'base64'),
        credentialPublicKey,
        counter: credential.counter,
      },
    });

    if (verification.verified) {
      await usersCollection.updateOne(
        { username, 'credentials.credentialID': credential.credentialID },
        { $set: { 'credentials.$.counter': verification.authenticationInfo.newSignCount } }
      );

      res.send({ verified: true });
    } else {
      res.status(400).send({ message: 'Verification failed' });
    }
  } catch (error) {
    console.error("Error verifying assertion:", error);
    res.status(500).send({ message: 'Error verifying assertion', error: error.message });
  }
});
