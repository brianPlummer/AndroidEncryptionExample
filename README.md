Android Encryption Example
========================

This is an encryption example of RSA and AES (CBC, ECB, CTR) 256 bit key on android with unit tests. I have 
tried to provide a good and secure example by showcasing:

* AES 256 bit key
* CBC/CTR/ECB example
* using salt for key derivation
* streams for arbitrary data sizes
* unit tests
* RSA 2048

The example encrypts the inputted string using AES, encrypts the key via RSA, and does the reverse when
the decrypt button is clicked.

