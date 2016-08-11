var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var random  = require("randomstring");

var app = express();

// Set hash algorithm
var algorithm = 'sha1'; //TODO chose korekt one: http://www.atmel.com/devices/ATECC508A.aspx --> P256

//Wire shark filter  ip.addr == 10.10.0.34
//TODO temp save für den chalenge
var challenge;
var tempDevicePublicKey;

module.exports = function(app) {
  var serviceRoutes = express.Router();


};

// view engine setup
//app.set('views', path.join(__dirname, 'views'));
//app.set('view engine', 'jade');

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

/**
 * Hack around. Refuse any get Request.
 * Post requests will be processed in the next function (get.all)
 */
app.get('/', function(req, res, next) {
    console.log("do not axept get, only post");
    res.status(405);
    res.send({message: 'This request is not valid.'});
});

/**
 * Processed all post requests
 */
app.all('/', function(req, res, next) {
   // var requestTyp= req.query();
   // console.log(requestTyp);
    var authStep= req.body.authStep;
    console.log("Authstep: " +authStep);
    if (authStep== "host-chain-verify") {//test sucesfull!
       // console.log("call F: verifyCert");
        veryifyCertificat(req,res,next)

    }else  if (authStep== "host-verify-resp"){
        console.log("call F: verifyResp----------------------");
        verifyRespons(req,res,next);
    } else{
        res.status(400);
        res.send('Sry. This is not a valid Request. ');
    }

});

/**
 * Check if the RoT certificate on the device is valid.
 * If yes: store the public key of the device and start a challenge to verify the key pair.
 * @param req Default HTTP nodeJs prams.
 * @param res Default HTTP nodeJs prams.
 * @param next Default HTTP nodeJs prams.
 * @returns {*}
 */
function veryifyCertificat(req, res, next){
    var body = req.body;
    var url = req.url;
    var cert = req.body.cert;
   // console.log("Hallo ESP it is", new Date().toString());
   // console.log("Cert--------------------------------------------------");
     console.log(body);
   // console.log(cert);
   // console.log("Cert decoded--------------------------------------------------");

    //TODO _LL erweiterung, cert überprüfen? --> nicht mehr während diser arbeit
    // Erweiterung Cert korekt erstellen. und übeprüfen
    var buffer = new Buffer(cert, 'base64');
   // var buffer =  Buffer.from(cert, 'base64');

  //  console.log(buffer.toString());



    /**
     * direktly start a chaleng
     */
    // Create challenge
    challenge = random.generate(32);//Math.round(Math.random()*99999999);//
    // response including signature and challenge
    console.log("chaleng:**********************************");
    console.log(challenge);
    const buf= Buffer (challenge);
    var challengeBuffer = buf.toString('base64');
    console.log(challengeBuffer);
    return res.status(201).send({
        success: true,

        //message: 'verify the signature with the root public-key and sign the challange with the device private-key',
        //signature: signatureArray,
        challenge: challengeBuffer
    });

}


/**
 * Verify if the challenge has been respond correctly.
 * If yes, send the MQTT credential to the device, later could be a token or other information. Store definitively device in DB
 * @param req Default HTTP nodeJs prams.
 * @param res Default HTTP nodeJs prams.
 * @param next Default HTTP nodeJs prams.
 */
function verifyRespons(req, res, next){
    console.log("verifyRespons");

//TODO Alternative lib https://github.com/indutny/elliptic
    // Get request data
    var deviceId = req.body.deviceId; // String
    var signature = req.body.signature; // Array
    var deviceRespons = req.body.resp;

    Device.findOne({deviceId: deviceId}, function(err, device) {
     //   if (err) throw err;

        //(device && !INVALID_DEVICE_ID) {

            // Create signature-buffer (split array in r and s)
            var length = signature.length;

            var r = signature.slice(0, length/2);
            var s = signature.slice(length/2);

            var signatureBuffer = serializeSig(r, s);

            // Get device public-key
            var keyBuffer = new Buffer(tempDevicePublicKey);
            var publicKey = ecdh.PublicKey.fromBuffer(curve, keyBuffer);

            // Create challange-buffer
            var challengeBuffer = new Buffer(challenge);

            // validate the signature with challenge and device public-key
            var isValid = publicKey.verifySignature(challengeBuffer, signatureBuffer);
            console.log('Challenge-Signature is', isValid ? 'valid' : 'invalid');

        var INVALID_CHALLENGE_SIG = false;
        if (isValid && ! INVALID_CHALLENGE_SIG) {

                // create token
                //var token = jwt.sign({c: challenge}, app.get

                // expiresIn: 30 // 10s
                // expiresIn: "24h"
               // expiresIn: "30 days"

                //console.log("Token: " + token);

                // response including token

                return res.status(201).send({
                    success: true,
                    message: 'use this token for service requests',//Add Mqtt credentials
                    token: token
                   });

        } else {
            return res.status(401).send({
                success: false,
                message: 'Authentication failed' });
        }


    });
}






// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      message: err.message,
      error: err
    });
  });
}





// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: {}
  });
});




module.exports = app;
