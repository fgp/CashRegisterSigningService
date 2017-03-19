# Introduction

CashRegisterSigningService provides a simple REST API to digitally sign
a receipt according to the austrian "Registrierkassenverordnung" using
a smart card issued by "A-Trust".

The card must be accessible via the javax.smartcardio API. On most
operating systems (macOS, Windows, Linux), this is usually the case for
USB smart card readers.

CashRegisterSigningService does not perform any other functions except
the parts that strictly require access to the smart card. Construction
and hashing (with SHA256) of the digital receipt are expected to happen
before CashRegisterSigningService is invoken - the service then simply
encrypts the hash of the receipt using the private key stored on the card,
and returns the resulting signature.

The PIN of the smart card defaults to "123456" but can be changed

# API

A signature is created by performing a GET request on

> http://127.0.0.1:PORT/sign?hash=[base64url-encoded sha256 hash]

If the server responds with status code 200 (OK), the body contains the
signature, also encoded as Base64URL. If the server responds with
any other status code, the request failed and the body contains an error
message.

# Building

The CashRegisterSigningService.jar can be built using apache ant.

> ant -f build-jar.xml 

# Running 

If run without additional arguments, the service runs on the default
port (897) and assumed the smart card is set to the default PIN

> java -jar CashRegisterSigningService.jar

Port, PIN, log file and log level can be changed, see

> java -jar CashRegisterSigningService.jar --help

