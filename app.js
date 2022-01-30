var express = require('express');
var logger = require('morgan');
var __ = require('underscore');
var cons = require('consolidate');
var randomstring = require("randomstring");
var fetch = require("node-fetch")
var app = express();
var btoa = require('btoa');
var session = require('express-session');


var base64url = require('base64url');
var crypto = require('crypto');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.engine('html', cons.underscore);
app.use('/static', express.static(__dirname + '/public'));
app.set('view engine', 'html');
app.set('views', 'public');
app.use(session({
    secret: 'sec',
    resave: true,
    saveUninitialized: true
}))

app.listen(process.env.port || 3000);

const redirectUri = "http://localhost:3000/redirect";
const scope = ["read", "write", "openid", "profile", "email", "phone"];

const clientId = 1;
const clientSecret = "sec123"

const responseType = ["code", "id_token"]

var keys;
var wellKnown;

//fetching jwks
const wellKnownEndpoint = "http://localhost:4567/.well-known/openid-configuration"

const fetchAsData = async () => {
    var wellKnownResponse = await fetch(wellKnownEndpoint)
    wellKnown = await wellKnownResponse.json()

    keysResponse = await fetch(wellKnown.jwks_uri)
    keys = await keysResponse.json()
}

fetchAsData();

app.get("/", (request, response) => {

    var state = randomstring.generate(20)
    var code_verifier = randomstring.generate(20)

    request.session.state = state
    request.session.code_verifier = code_verifier

    var code_challenge = base64url.fromBase64(crypto.createHash('sha256').update(code_verifier).digest('base64'))

    response.render("index.html", {
        as_uri: `${wellKnown.authorization_endpoint}?client_id=${clientId}&redirect_uri=${redirectUri}&scope=${scope.join("%20")}&state=${state}`
            + `&code_challenge=${code_challenge}&code_challenge_method=S256&response_type=${responseType.join("%20")}&nonce=12345`
    })
})

app.get("/redirect", async (request, response) => {

    var state = request.query.state

    if (request.session.state !== state) {
        response.sendStatus(401)
        return;
    }

    var code = request.query.code

    const clientCredentials = clientId + ":" + clientSecret;

    var res = await fetch(wellKnown.token_endpoint, {
        method: 'POST', body: JSON.stringify({ code: code, code_verifier: request.session.code_verifier, grant_type: "authorization_code" }), headers: {
            'Content-Type': 'application/json',
            'Authorization': "Basic " + btoa(clientCredentials),
        }
    })
    var resBody = await res.json()
    request.session.access_token = resBody.access_token
    //TODO verifiying id_token signature
    response.render("redirect.html", {
        expiry: res.expiry,
        id_token: Buffer.from(resBody.id_token, 'base64')

    })
})

app.get("/resource", async (request, response) => {

    var res = await fetch(wellKnown.userinfo_endpoint, {
        method: 'GET', headers: {
            'Content-Type': 'application/json',
            'Authorization': "Bearer " + request.session.token,
        }
    })

    if (res.status != 200) {
        response.status(401).send();
        return;
    }

    response.status(200).send()
    return;
})

app.get("/revoke", async (request, response) => {

    const clientCredentials = clientId + ":" + clientSecret;

    var res = await fetch(wellKnown.revocation_endpoint, {
        method: 'POST', body: JSON.stringify({ token: request.session.token }), headers: {
            'Content-Type': 'application/json',
            'Authorization': "Basic " + btoa(clientCredentials)
        }
    })

    if (res.status != 200) {
        response.status(401).send();
        return;
    }

    response.status(200).send()
    return;
})