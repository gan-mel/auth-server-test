'use strict';

const fs = require('fs');
const express = require('express');
const jwt = require('jsonwebtoken');
const _ = require('lodash');
const NodeCache = require('node-cache');
const { v4: uuidv4 } = require('uuid');
const dotenv = require('dotenv');
dotenv.config();

const config = process.env.ENVIRONMENT || 'development';

const Logger = require('../lib/logger/logger');

const log = new Logger('routes/auth');
const router = express.Router();

// use the global csds instance created in app.js for the APIs that need it
const leAPIs = require('../lib/le_apis');
const csds = global.csds;
const oauth = {
    consumer_key: process.env.OAUTH_KEY,
    consumer_secret: process.env.OAUTH_SECRET
};
const visitInfoAPI = new leAPIs.VisitInfoAPI({csds, oauth})
const codeCache = new NodeCache({
    stdTTL: 30
});

const pubKey = fs.readFileSync(__dirname + '/../cert/public_key_idp.pem', 'utf-8')
const privKey = fs.readFileSync(__dirname + '/../cert/private_key_idp.pem', 'utf-8')
const ttlSec = 86400

const pubKeyString = pubKey ? pubKey.replace(/(-{5}[\w\s]+-{5})|\n/g,'') : undefined;

router.get('/pubkey', getPubKey);
router.get('/config', getConfig);
router.post('/token', token);
router.get('/token', tokenRedirect);
router.post('/code', code);
router.get('/code', codeRedirect);
router.get('/delegate', delegate);
router.get('/delegatedData', delegatedData);

module.exports = router;

// request handlers
function getPubKey (req, res) {
    log.info('public key requested')
    if (pubKeyString) res.status(200).send(pubKeyString)
    else res.status(404).send()
}

function getConfig (req, res) {
    log.info('configuration info requested')
    let authConfig = {
        implicit: {
            'LE Settings': {
                'Authentication Endpoint': `${process.env.host}api/auth/token`
            }
        },
        code: {
            'LE Settings': {
                'Authentication Endpoint': `${process.env.host}api/auth/code`,
                'Token Endpoint': `${process.env.host}api/auth/token`,
                'Client ID': '[Site ID]',
                'Client Secret': 'Secret'
            }
        }

    }

    if (pubKey) authConfig.both = { 'JWT Public Key': pubKeyString }
    res.status(200).send(authConfig);
}

function token (req, res) {
    log.info('token requested')
    // code flow
    if (req.body && req.body.grant_type === 'authorization_code') {
        let details = codeCache.get(req.body.code)
        if (details) {
            let token = generateJWT(details.payload, details.ttl)
            if (token) {
                let response = {
                    access_token: token,
                    id_token: token,
                    token_type: 'bearer',
                    expires_in: details.ttl | ttlSec
                }
                // delegation token requires scope
                if (details.scope) response.scope = details.scope
                res.status(200).send(response);
            }
            else res.status(404).send('couldnae make token')
        } else res.status(404).send('couldnae find code')
    // implicit flow (direct token request from page)
    } else {
        let token = generateJWT(req.body && req.body.payload, req.body && req.body.ttl)
        if (token) res.status(200).send(token)
        else res.status(404).send('couldnae make token')
    }
}

async function tokenRedirect (req, res) {
    log.info('token redirect requested')
    if (!req.query.redirect_uri) res.status(400).send('redirect_uri param required')
    let redirect = new URL(req.query.redirect_uri)
      ,params = new URLSearchParams(redirect.search)
      ,windowConfig;

    // OAuth 2 RFC version of auth connector - window configuration is in the "state" parameter
    // "state" parameter must be added to the redirect_uri
    if (req.query.response_type === 'id_token') {
        params.append('state',req.query.state);
        windowConfig = JSON.parse(req.query.state).lpUnifiedWindowConfig;
        // openID version of auth connector - window config is already in redirect_uri
    } else {
        windowConfig = JSON.parse(redirect.searchParams.get('lpUnifiedWindowConfig'));
    }

    let visitInfo, sub, payload;
    // try to get the visit info for this shark session
    try {
        visitInfo = await visitInfoAPI.get(windowConfig.accountId, windowConfig.engConf.svid, windowConfig.engConf.ssid)
    } catch (e) { log.warn(`windowConfig lacks accountId, svid, or ssid`) }

    // try to set the sub from the unauth customerId sde
    try {
        sub = visitInfo.appSessions[0].customerInfo.customerInfo.customerId
    } catch (e) { log.warn('unable to extract customerId from shark session') }

    // if the above failed try to set the sub from the window config
    if (!sub) {
        try {
            sub = windowConfig.engConf.svid
        } catch (e) { log.warn('unable to set sub from vid') }
    }

    // if we have a sub use it
    if (sub) payload = { sub };
    let token = generateJWT(payload)

    params.append('token', token);
    redirect.search = params;
    res.redirect(redirect.href);
}

function code (req, res) {
    log.info('code requested')
    let code = uuidv4();
    if (code) {
        codeCache.set(code, req.body)
        res.status(200).send(code)
    } else {
        res.status(404).send('couldnae make code')
    }
}

async function codeRedirect (req, res) {
    log.info('code redirect requested')
    if (!req.query.redirect_uri) res.status(400).send('redirect_uri param required')

    let redirect = new URL(req.query.redirect_uri)
      ,params = new URLSearchParams(redirect.search)
      ,windowConfig;

    // OAuth 2 RFC version of auth connector - window configuration is in the "state" parameter
    // "state" parameter must be added to the redirect_uri
    if (req.query.response_type === 'code') {
        params.append('state',req.query.state);
        windowConfig = JSON.parse(req.query.state).lpUnifiedWindowConfig;
        // openID version of auth connector - window config is already in redirect_uri
    } else {
        windowConfig = JSON.parse(redirect.searchParams.get('lpUnifiedWindowConfig'));
    }

    let visitInfo, sub, payload;
    // try to get the visit info for this shark session
    try {
        visitInfo = await visitInfoAPI.get(windowConfig.accountId, windowConfig.engConf.svid, windowConfig.engConf.ssid)
    } catch (e) { log.warn(`windowConfig lacks accountId, svid, or ssid`) }

    // try to set the sub from the unauth customerId sde
    try {
        sub = visitInfo.appSessions[0].customerInfo.customerInfo.customerId
    } catch (e) { log.warn('unable to extract customerId from shark session') }

    // if the above failed try to set the sub from the window config
    if (!sub) {
        try {
            sub = windowConfig.engConf.svid
        } catch (e) { log.warn('unable to set sub from vid') }
    }

    let code = uuidv4();
    if (code) {
        // if we have a sub use it
        codeCache.set(code, { payload: { sub }})
        params.append('code', code);
        redirect.search = params;
        res.redirect(redirect.href);
    } else {
        res.status(404).send('couldnae make code')
    }
}



async function delegate (req, res) {
    let redirect = new URL(req.query.redirect_uri),
      params = new URLSearchParams(),
      code = uuidv4();


    if (code) {
        codeCache.set(code, {
            payload: {
                iss: 'support_api_delegator'
            },
            state: req.query.state,
            scope: req.query.scope
        })
        params.append('code', code);
        params.append('state',req.query.state);
        redirect.search = params;
        res.redirect(redirect);
    } else {
        res.status(404).send('couldnae make code')
    }
}

function generateJWT (payload, ttl) {
    log.debug('generating jwt')
    let nowSec = Math.round(new Date().getTime() / 1000)
    // generate default payload
    let _payload = {
        iss: 'support_api',
        iat: nowSec,
        exp: nowSec + ttlSec,
        sub: Math.random().toString(36).substring(2)
    }
    // merge provided payload with default
    if (payload) _.merge(_payload, payload)
    // set iat from ttl if provided
    if (ttl) _payload.exp = _payload.iat + ttl

    return jwt.sign(_payload, privKey, { algorithm: 'RS256'});
}

function delegatedData (req, res) {
    log.debug(`delegation authorization: ${req.headers.authorization}`)
    if (req.headers.authorization === 'Bearer {$botContext.cidp_accessToken}') {
        res.status(401).send();
    } else {
        res.status(200).send('here\'s yer data!')
    }
}