var sdk = require('postman-collection');
var crypto = require("crypto-js");
 
//get api key and key id
var APIKeyId = pm.environment.get("api_key_id"),
APIKey = pm.environment.get("api_key");
 
//get ISO date
function ISODateString(d) {
function pad(n) {
return n < 10 ? '0' + n : n
}
return d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + 
pad(d.getUTCDate()) + 'T' + pad(d.getUTCHours()) + ':' + 
pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds()) + 'Z'
}
 
//generate base64url by using cryptojs
function base64url(input) {
var base64String = crypto.enc.Base64.stringify(input);
return urlConvertBase64(base64String);
}
 
//convert base64url to base64
function debase64url (str) {
return (str + '==='.slice((str.length + 3) % 4))
.replace(/-/g, '+')
.replace(/_/g, '/')
}
 
//convert to base 64 url
function urlConvertBase64(input) {
var output = input.replace(/=+$/, '');
output = output.replace(/\+/g, '-');
output = output.replace(/\//g, '_');
 
return output;
}
 
var replaceVars = function(string)
{
return string.toString().replace(/{{.+?}}/g, function(match)
{
var varName = match.substr(2, match.length - 4);
var varValue = pm.environment[varName] || pm.globals[varName];
return varValue ? replaceVars(varValue) : match; // recursive!
});
};
 
 
// get 32 bytes random;
var random = crypto.lib.WordArray.random(16);
 
//get path expanding any variables that exist
var fullPath = replaceVars(pm.request.url);
var loc = new sdk.Url(fullPath);
var path = loc.getPath();
 
//generate canonicalizedHeader
var ref = pm.request.headers.toObject(true);
var canonicalizedHeader = "";
 
for (var key in ref) {
 
//only headers with "verint-" prefix can be used
if (key.substring(0, 7).toLowerCase() != "verint-") continue;
 
canonicalizedHeader += (key + ":");
var value = ref[key];
 
canonicalizedHeader += value;
canonicalizedHeader += "\n";
}
 
//make canonicalizedHeader it lower case
canonicalizedHeader = canonicalizedHeader.toLowerCase();
 
//get String to sign
var salt = base64url(random);
var method = pm.request.method;
var issuedAt = ISODateString(new Date());
 
var stringToSign = salt + "\n" + method + "\n" + path + "\n" + issuedAt +
"\n" + canonicalizedHeader + "\n";
 
var hash = crypto.HmacSHA256(stringToSign, 
crypto.enc.Base64.parse(debase64url(APIKey)));
 
//get an signature
var signature = crypto.enc.Base64.stringify(hash);
 
//String prefix
var verintAuthId = "Vrnt-1-HMAC-SHA256";
 
//Generate Authorization Header Value
var authHeaderValue = verintAuthId + " " + "salt=" + salt + "," + "iat=" + 
issuedAt + "," + "kid=" + APIKeyId + "," + "sig=" + 
urlConvertBase64(signature);
 
pm.globals.set("Authorization", authHeaderValue);