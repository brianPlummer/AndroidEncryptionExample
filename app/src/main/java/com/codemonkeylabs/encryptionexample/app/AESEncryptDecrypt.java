package com.codemonkeylabs.encryptionexample.app;

import android.util.Base64;
import android.util.Log;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by brianplummer on 4/29/14.
 */
public class AESEncryptDecrypt {


    //16 byte key....other sizes allowed.....getBytes defaults to utf-8
    public static final String NOT_SECRET_ENCRYPTION_KEY = "1234567812345678";
    //Must be 16 bytes long....getBytes defaults to utf-8
    private static final String IVS = "1234567812345678";


    public String encrypt(String inData, byte[] key){
        byte[] encryptedData = aesEncrypt(inData.getBytes(), key,
                IVS.getBytes());
        return new String(Base64.encode(encryptedData,Base64.NO_WRAP));
    }

    public String decrypt(String inData, byte[] key){
        byte[] decryptData = aesDecrypt(Base64.decode(inData,Base64.NO_WRAP),
                key,IVS.getBytes());
        return new String(decryptData);
    }

    //Ripped from:
    // http://stackoverflow.com/questions/13579326/aes-128-encryption-in-android-and-net-with-custom-key-and-iv

    public static byte[] aesEncrypt(byte[] data, byte[] key, byte[] ivs) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            IvParameterSpec ivps = new IvParameterSpec(ivs);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivps);
            return cipher.doFinal(data);
        } catch (Exception e) {
            Log.e("##########",e.getMessage(),e);
        }
        return null;
    }

    public static byte[] aesDecrypt(byte[] data, byte[] key, byte[] ivs) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            IvParameterSpec ivps = new IvParameterSpec(ivs);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivps);
            return cipher.doFinal(data);
        } catch (Exception e) {
            Log.e("##########",e.getMessage(),e);
        }
        return null;
    }

}
