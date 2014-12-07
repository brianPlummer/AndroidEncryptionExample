package com.codemonkeylabs.encryptionexample.app;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * RSA Helper Encryption Class
 * Created by brianplummer on 4/29/14.
 */
public class RSAEncryptDecrypt {

    //key length
    public static final int KEY_LENGTH = 2048;
    //main family of rsa
    public static final String RSA = "RSA";


    public static KeyPair generateRSAKey()
    {
        KeyPairGenerator kpg = null;
        try
        {
            kpg = KeyPairGenerator.getInstance(RSA);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException(e);
        }
        kpg.initialize(KEY_LENGTH);
        return kpg.genKeyPair();
    }


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
            throw new RuntimeException(e);
        }

        return enc;
    }

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
            throw new RuntimeException(e);
        }
        return plain;
    }

}
