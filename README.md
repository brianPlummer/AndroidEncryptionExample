[![Android Arsenal](https://img.shields.io/badge/Android%20Arsenal-AndroidEncryptionExample-green.svg?style=true)](https://android-arsenal.com/details/3/4886)

Android Encryption Example
========================

This example encrypts the inputted string using AES, encrypts the key via RSA, and does the reverse when
the decrypt button is clicked.

We start by encrypting the plain text with AES

```java
byte[] iv = AESEncryptDecrypt.aesEncrypt(plainTextInputStream,
                "secret key".toCharArray(),
                "AES/ECB/PKCS5PADDING",
                encOutputStream);
```
We then combine the outputted IV and the key we used:

```java
byte[] combined = Util.concat("secret key".getBytes(), iv);
```

Lastly we encryt the IV and key using an RSA public key:

```java
byte[] encryptedAESKeyIV = RSAEncryptDecrypt.encryptRSA(combined, rsaKey.getPublic());
```

======================== 

This is an encryption example of RSA and AES (CBC, ECB, CTR) 256 bit key on android with unit tests. I have 
tried to provide a good and secure example by showcasing:

* AES 256 bit key
* CBC/CTR/ECB example
* using salt for key derivation
* streams for arbitrary data sizes
* unit tests
* RSA 2048 bit
* Spongy Castle (Android version of Bouncy Castle encryption library)


![AndroidEncryptionExample](https://github.com/brianPlummer/AndroidEncryptionExample/raw/master/assets/encryption_sample.gif "AndroidEncryptionExample")


Prerequisite
========================

In order to build the apk and run tests you must have the JCE (Java Cryptogrpahy Extension) Unlimited Strength policy jars installed for your JRE runtime.  

* JCE download for java 8: http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html

If you do not do this then you will see the error:
```
java.lang.RuntimeException: java.security.InvalidKeyException: Illegal key size or default parameters
```

Testing/Building
========================

To run the unit tests
```
./gradlew clean test
```

To build and install apk:
```
./gradlew clean installDebug
```

