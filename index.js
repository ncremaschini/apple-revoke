
'use strict';
require('dotenv').config()
var axios = require("axios");
var qs = require("qs");
var jwt = require("jsonwebtoken");
var fs = require("fs");

const authCode =  process.env.AUTH_CODE;
const team_id = process.env.TEAM_ID;
const client_id = process.env.CLIENT_ID;
const kid = process.env.KEY_ID;
const key_filename = process.env.KEY_FILENAME;

let client_secret = makeJWT()
console.log("client secret:" + client_secret);

getRefreshToken(client_secret)
  .then( refresh_token => {
    console.log("refresh token: " +  refresh_token)
    if(refresh_token){
      revokeToken(client_secret, refresh_token);
    }
  });


function makeJWT() {
  console.log("generating jwt");
  
  let privateKey = fs.readFileSync(key_filename);

  let token = jwt.sign(
    {
      iss: team_id,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 120,
      aud: "https://appleid.apple.com",
      sub: client_id
    },
    privateKey,
    {
      algorithm: "ES256",
      header: {
        alg: "ES256",
        kid: kid,
      },
    }
  );

  return token;
}

async function getRefreshToken(client_secret) {
  console.log("getting refresh token");

  let data = {
    code: authCode,
    client_id: client_id,
    client_secret: client_secret,
    grant_type: "authorization_code",
  };

  let response = await axios.post(`https://appleid.apple.com/auth/token`, qs.stringify(data), {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });

  return response.data.refresh_token;

}

function revokeToken(client_secret, refresh_token) {
  console.log("revoking refresh token");

  let data = {
    token: refresh_token,
    client_id: client_id,
    client_secret: client_secret,
    token_type_hint: "refresh_token",
  };

  return axios
    .post(`https://appleid.apple.com/auth/revoke`, qs.stringify(data), {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    })
    .then(async (res) => {
      console.log(res);
    });
}
