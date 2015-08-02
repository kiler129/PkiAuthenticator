# PKI Authenticator Server

Currently no documentation is provided, since project is in development and not ready to use by general public.

## NEVER EVER USE SAMPLE KEYS IN PRODUCTION ENVIRONMENT!
To get your own just use openssl:
```
openssl genrsa -out private_key.pem 4096
openssl rsa -pubout -in private_key.pem -out public_key.pem
```
Keep in mind server should store it's **private** key and service **public** keys (never private ones!). However it's not a security risk to store server public key within keys folder.