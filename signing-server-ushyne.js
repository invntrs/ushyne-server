var express = require('express'),
    http = require('http'),
    path = require('path'),
    crypto = require('crypto'),
    app = express(),
    bucket = "ushyne",
    awsKey = "AKIAJ777OSUKHQV6LEWQ",
    secret = "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";

app.use(express.logger("dev"));
app.use(express.methodOverride());
//app.use(express.bodyParser());
app.use(express.json());
app.use(express.urlencoded());
app.use(app.router);

function sign(req, res, next) {

    var fileName = req.body.fileName,
        expiration = new Date(new Date().getTime() + 1000 * 60 * 30).toISOString(); // expire in 30 minutes

    var policy =
    { "expiration": expiration,
        "conditions": [
            {"bucket": bucket},
            {"key": fileName},
            {"acl": 'public-read'},
            ["starts-with", "$Content-Type", ""],
            ["content-length-range", 0, 1048576000]
        ]};

    policyBase64 = new Buffer(JSON.stringify(policy), 'utf8').toString('base64');
    signature = crypto.createHmac('sha1', secret).update(policyBase64).digest('base64');
    res.json({bucket: bucket, awsKey: awsKey, policy: policyBase64, signature: signature});

}

// DON'T FORGET TO SECURE THIS ENDPOINT WITH APPROPRIATE AUTHENTICATION/AUTHORIZATION MECHANISM
app.post('/signing', sign);

app.listen(3000, function () {
    console.log('Server listening on port 3000');
});
