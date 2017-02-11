package com.codemonkeylabs.encryptionexample.app;

import android.util.Log;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
/**
 * RSA Helper Encryption Class
 */
public class RSAEncryptDecrypt {

    //key length
    public static final int KEY_LENGTH = 2048;
    //main family of rsa
    public static final String RSA = "RSA";

    /**
     * generate a 2048 bit RSA key
     *
     * @return a 2048 bit rsa key
     */
    public static KeyPair generateRSAKey()
    {
        KeyPairGenerator kpg = null;
        try
        {
            //get an RSA key generator
            kpg = KeyPairGenerator.getInstance(RSA);
        }
        catch (NoSuchAlgorithmException e)
        {
            Log.e(RSAEncryptDecrypt.class.getName(), e.getMessage(), e);
            throw new RuntimeException(e);
        }
        //initialize the key to 2048 bits
        kpg.initialize(KEY_LENGTH);
        //return the generated key pair
        return kpg.genKeyPair();
    }

    /**
     * main RSA encrypt method
     *
     * @param plain     plain text you want to encrypt
     * @param publicKey public key to encrypt with
     * @return          encrypted text
     */
    public static byte[] encryptRSA(byte[] plain, PublicKey publicKey)
    {
        byte[] enc = null;
        try
        {
            Cipher cipher = Cipher.getInstance(RSA);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            enc = cipher.doFinal(plain);
        }
        //no need to catch 4 different exceptions
        catch (Exception e)
        {
            Log.e(RSAEncryptDecrypt.class.getName(), e.getMessage(), e);
            throw new RuntimeException(e);
        }

        return enc;
    }

    /**
     *  main RSA decrypt method
     *
     * @param enc           encrypted text you want to dcrypt
     * @param privateKey    private key to use for decryption
     * @return              plain text
     */
    public static byte[] decryptRSA(byte[] enc, PrivateKey privateKey)
    {
        byte[] plain = null;
        try
        {
            Cipher cipher = Cipher.getInstance(RSA);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            plain = cipher.doFinal(enc);
        }
        //no need to catch 4 different exceptions
        catch (Exception e)
        {
            Log.e(RSAEncryptDecrypt.class.getName(), e.getMessage(), e);
            throw new RuntimeException(e);
        }
        return plain;
    }

}
