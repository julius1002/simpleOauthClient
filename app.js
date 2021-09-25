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

const applicationPort = process.env.port || 3000;

app.listen(applicationPort);

console.log("Express listenting on " + applicationPort)

var asUri = "http://localhost:4567"

var tokenEndpoint = "/token"

var redirectUri = "http://localhost:3000/redirect";

var scope = ["read", "write"];

var clientId = 1;

var clientSecret = "sec123"

app.get("/", (request, response) => {

    var state = randomstring.generate(20)

    var code_verifier = randomstring.generate(20)

    request.session.state = state

    request.session.code_verifier = code_verifier

    var code_challenge = base64url.fromBase64(crypto.createHash('sha256').update(code_verifier).digest('base64'))

    response.render("index.html", {
        as_uri: `${asUri}/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&scope=${scope.join("%20")}&state=${state}`
            + `&code_challenge=${code_challenge}&code_challenge_method=S256&response_type=code`
    })
})

app.get("/redirect", (request, response) => {

    var state = request.query.state

    if (request.session.state !== state) {
        response.sendStatus(401)
        return;
    }

    var code = request.query.code

    const clientCredentials = clientId + ":" + clientSecret;

    fetch(asUri + tokenEndpoint, {
        method: 'POST', body: JSON.stringify({ code: code, code_verifier: request.session.code_verifier, grant_type: "authorization_code" }), headers: {
            'Content-Type': 'application/json',
            'Authorization': "Basic " + btoa(clientCredentials),
        }
    }).then(res => res.json()).then(res => {
        request.session.token = res.token
        response.render("redirect.html", {
            expiry: res.expiry
        })
    })
})

app.get("/resource", async (request, response) => {

    var res = await fetch("http://localhost:8080/resource", {
        method: 'GET', headers: {
            'Content-Type': 'application/json',
            'Authorization': "Bearer " + request.session.token,
        }
    })


    console.log(res.status)
    if (res.status != 200) {
        response.status(401).send();
        return;
    }

    response.status(200).send()
    return;
})

app.get("/revoke", async (request, response) => {

    const clientCredentials = clientId + ":" + clientSecret;

    var res = await fetch("http://localhost:4567/revoke", {
        method: 'POST', body: JSON.stringify({ token: request.session.token }), headers: {
            'Content-Type': 'application/json',
            'Authorization': "Basic " + btoa(clientCredentials)
        }
    })

    console.log(res.status)
    if (res.status != 200) {
        response.status(401).send();
        return;
    }

    response.status(200).send()
    return;
})

