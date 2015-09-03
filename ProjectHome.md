The other day I was trying to write a simple program to be able to verify the digital signature on a file that at some point earlier I would have signed. I didn't need any special "Cryptographic Key Store" or fancy Root Authority verification.

I found this to be exceedingly complex with the built-in Cryptographic APIs. This library is built on top of those APIs and provides three simple functions: `GenerateKeyPair`, `SignFile`, `VerifyFile`.

These functions do exactly what you would expect...

`GenerateKeyPair` outputs two files a public key and a private key.

`SignFile` takes a private key file and a file to sign and outputs a third signed file.

`VerifyFile` takes a public key and a previous signed file and tells whether it was signed with the corresponding private key and if so, it outputs the original unsigned file.