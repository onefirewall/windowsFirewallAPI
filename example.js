// Init dependencies 
var express = require('express'),
    ipfilter = require('express-ipfilter').IpFilter;

//var IpDeniedError = new Error(); //???
// Blacklist the following IPs 
var ips = ['127.0.0.1'];

var app = express()
 
// Create the server 
app.use(ipfilter(ips, {mode: 'allow'})); // refuse connection on localhost
//app.use(ipfilter(ips)); // allow everything apart 127.0.0.1

console.log("Starting server on 3000 using ips");
app.listen(3000).on('IpDeniedError', console.log);

//IpDeniedError exception required
if (app.get('env') === 'development') {
    app.use(function(err, req, res, _next) {
        console.log('Error handler', err);
        if (err instanceof IpDeniedError) {
           res.status(401);
        } else {
          res.status(err.status || 500);
        }

        res.render('error', {
            message: 'You shall not pass',
            error: err
        });
    });
}
