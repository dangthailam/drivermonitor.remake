const express = require('express')
const cors = require('cors')
const bodyParser = require('body-parser')
const OktaJwtVerifier = require('@okta/jwt-verifier')

const oktaJwtVerifier = new OktaJwtVerifier({
    clientId: '{clientId}',
    issuer: 'https://dev-673280.oktapreview.com/oauth2/default'
})

let app = express()
app.use(cors())
app.use(bodyParser.json())

// verify JWT token middleware
app.use((req, res, next) => {
    // require every request to have an authorization header
    if (!req.headers.authorization) {
        return next(new Error('Authorization header is required'))
    }
    let parts = req.headers.authorization.trim().split(' ')
    let accessToken = parts.pop()
    oktaJwtVerifier.verifyAccessToken(accessToken)
        .then(jwt => {
            req.user = {
                uid: jwt.claims.uid,
                email: jwt.claims.sub
            }
            next()
        })
        .catch(next) // jwt did not verify!
})

app.listen(8081, () => {
    console.log('listening to port localhost:8081')
})