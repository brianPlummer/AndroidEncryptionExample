package com.codemonkeylabs.encryptionexample.app;


import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES Helper Encryption Class
 */
public class AESEncryptDecrypt {

    //32 byte key -> 256 bit.....getBytes defaults to utf-8
    public static final String NOT_SECRET_ENCRYPTION_KEY = "12345678123456781234567812345678";
    //type of aes key that will be created
    public static final String SECRET_KEY_TYPE = "PBKDF2WithHmacSHA1";
    //value used for salting....can be anything
    public static final String salt = "some_salt";
    //length of key
    public static final int KEY_LENGTH = 256;
    //number of times the password is hashed
    public static final int ITERATION_COUNT = 65536;
    //main family of aes
    public static final String AES = "AES";
    //spongy castle security provider
    public static String SECURITY_PROVIDER = "SC";

    /*
     * YOU HAVE TO CALL THIS BEFORE ENCRYPT/DECRYPT TO SET PROVIDER
     * i added it this way for ease of distinction when unit testing...
     * unit test requires bouncyCastle and on android we want
     * spongyCastle....in the real world you would inject this
     * dependency via dagger..
     */
    public static void setProvider(Provider provider, String providerName) {
        SECURITY_PROVIDER = providerName;
        Security.insertProviderAt(provider, 1);
    }

    /*
     * helper enum class that contains the aes ciphers that we
     * support
     */
    public enum AESCipherType {
        AES_CIPHER_CTR_NOPADDING("AES/CTR/NOPADDING"),
        AES_CIPHER_ECB_PKCS5PADDING("AES/ECB/PKCS5PADDING"),
        AES_CBC_PKCS5PADDING("AES/CBC/PKCS5Padding"),
        AES_CBC_PKCS7Padding("AES/CBC/PKCS7Padding");

        private final String value;

        AESCipherType(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    /**
     * main aes encryption method.  takes in the unencrypted data
     * as an inputstream and writes out the encrypted data
     * within the provided outputstream
     *
     * @param inData inputStream that represents the plaintext data
     * @param key unencoded and unencrypted aes key
     * @param aesCipherType enum representing what ciper to use boils down to a string
     * @param outData  outputstream where we write the encrypted data
     * @return IV generated from key creation
     */
    public static byte[] aesEncrypt(InputStream inData,
                                    char[] key,
                                    AESEncryptDecrypt.AESCipherType aesCipherType,
                                    OutputStream outData)
    {
        CipherOutputStream cos = null;
        try
        {
            //create the cipher from the passed in type using the specified security provider
            Cipher cipher = Cipher.getInstance(aesCipherType.getValue(), SECURITY_PROVIDER);
            //generate secret key
            SecretKey secret = getSecretKey(key);
            //init the cipher
            cipher.init(Cipher.ENCRYPT_MODE, secret);
            //create the cipher outputstream
            cos = new CipherOutputStream(outData, cipher);
            //copy the plaintext inputstream to the encrypted outputstream
            Util.copy(inData, cos);
            //query parameters for iv
            AlgorithmParameters params = cipher.getParameters();
            //check to see if we have an IV to return
            //some ciphers (ECB) don't create IV
            return params == null ? null : params.getParameterSpec(IvParameterSpec.class).getIV();
        }
        catch (Exception e)
        {
            Log.e(AESEncryptDecrypt.class.getName(), e.getMessage(), e);
            throw new RuntimeException(e);
        }
        finally
        {
            if(cos != null)
                try
                {
                    //close the stream
                    cos.close();
                } catch (IOException e) {
                    Log.e(AESEncryptDecrypt.class.getName(), e.getMessage(), e);
                    throw new RuntimeException(e);
                }
        }
    }

    /**
     * generates a secret key from the passed in raw key value
     * we create a 256 bit key that is salted using our example
     * salt value above
     *
     * @param key input key in a char array
     * @return a salted key of the type SECRET_KEY_TYPE
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeySpecException
     */
    private static SecretKey getSecretKey(char[] key) throws NoSuchAlgorithmException,
            UnsupportedEncodingException,
            InvalidKeySpecException,
            NoSuchProviderException
    {
        SecretKeyFactory factory = null;
        factory = SecretKeyFactory.getInstance(SECRET_KEY_TYPE,
                SECURITY_PROVIDER);

        KeySpec spec = new PBEKeySpec(key,
                salt.getBytes("UTF-8"),
                ITERATION_COUNT,
                KEY_LENGTH);

        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), AES);
    }

    /**
     * main aes decryption method. takes in the encrypted data
     * inputstream and writes the decrypted data to the provided
     * outputstream.
     *
     * @param inData inputStream that represents the encrypted data
     * @param key unencoded and unencrypted aes key
     * @param ivs unencoded and unencrypted iv
     * @param aesCipherType enum representing what ciper to use boils down to a string
     * @param outData outputstream where we write the decrypted data
     */
    public static void aesDecrypt(InputStream inData,
                                  char[] key,
                                  byte[] ivs,
                                  AESEncryptDecrypt.AESCipherType aesCipherType,
                                  OutputStream outData)
    {
        CipherInputStream cis = null;
        try
        {
            //create the cipher from the passed in type using the specified security provider
            Cipher cipher = Cipher.getInstance(aesCipherType.getValue(), SECURITY_PROVIDER);
            //generate secret key
            SecretKey secret = getSecretKey(key);
            //if ivs is passed in then we should use it to create the
            //cipher
            if( ivs == null)
            {
                cipher.init(Cipher.DECRYPT_MODE, secret);
            } else {
                IvParameterSpec ivps = new IvParameterSpec(ivs);
                cipher.init(Cipher.DECRYPT_MODE, secret, ivps);
            }
            //create the cipher inputstream
            cis = new CipherInputStream(inData, cipher);
            //copy the encrypted inputstream to the plaintext outputstream
            Util.copy(cis, outData);
        }
        catch (Exception e)
        {
            Log.e(AESEncryptDecrypt.class.getName(), e.getMessage(), e);
            throw new RuntimeException(e);
        }
        finally
        {
            if(cis != null)
                try
                {
                    //close the stream
                    cis.close();
                } catch (IOException e) {
                    Log.e(AESEncryptDecrypt.class.getName(), e.getMessage(), e);
                    throw new RuntimeException(e);
                }
        }
    }

}
