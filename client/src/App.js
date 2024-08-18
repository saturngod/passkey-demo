import React, { useState } from 'react';
import axios from 'axios';
import {
  startRegistration,
  startAuthentication,
} from '@simplewebauthn/browser';

function App() {
  const [username, setUsername] = useState('');
  const [registered, setRegistered] = useState(false);
  const [authenticated, setAuthenticated] = useState(false);

  const register = async () => {
    try {
      const options = await axios.post('http://localhost:3001/register-options', { username });
      const attResp = await startRegistration(options.data);
  
      // Prepare response object
      const response = {
        id: attResp.rawId,
        rawId: attResp.rawId,
        response: {
          attestationObject: attResp.response.attestationObject,
          clientDataJSON: attResp.response.clientDataJSON,
        },
        type: attResp.type,
      };
  
      const verification = await axios.post('http://localhost:3001/register',{ username: username, attestationResponse: response});
      setRegistered(verification.data.verified);
    } catch (error) {
      console.error('Registration failed', error);
    }
  };

  const authenticate = async () => {
    try {
      const options = await axios.post('http://localhost:3001/auth-options', { username });
      const assertionResponse = await startAuthentication(options.data);
      const verification = await axios.post('http://localhost:3001/authenticate', {username,assertionResponse});
      setAuthenticated(verification.data.verified);
    } catch (error) {
      console.error('Authentication failed', error);
    }
  };

  return (
    <div className="App">
      <h1>Passkey Demo</h1>
      <input
        type="text"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        placeholder="Enter username"
      />
      <button onClick={register}>Register</button>
      <button onClick={authenticate}>Authenticate</button>
      {registered && <p>Registered successfully!</p>}
      {authenticated && <p>Authenticated successfully!</p>}
    </div>
  );
}

export default App;
