package com.codemonkeylabs.encryptionexample.app;

import android.util.Log;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Created by brianplummer on 4/29/14.
 */
public class RSAEncryptDecrypt {

    private KeyPair keyPair = null;

    public RSAEncryptDecrypt(){
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            Log.e("#######",e.getMessage(),e);
        }
        kpg.initialize(2048);
        this.keyPair = kpg.genKeyPair();
    }


    public byte[] encrypt(byte[] plain){
        byte[] enc = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, this.keyPair.getPublic());
            enc = cipher.doFinal(plain);
        } catch (NoSuchAlgorithmException e) {
            Log.e("#######", e.getMessage(), e);
        } catch (NoSuchPaddingException e) {
            Log.e("#######", e.getMessage(), e);
        } catch (InvalidKeyException e) {
            Log.e("#######", e.getMessage(), e);
        } catch (BadPaddingException e) {
            Log.e("#######", e.getMessage(), e);
        } catch (IllegalBlockSizeException e) {
            Log.e("#######", e.getMessage(), e);
        }
        return enc;
    }

    public byte[] decrypt(byte[] enc){
        byte[] plain = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, this.keyPair.getPrivate());
            plain = cipher.doFinal(enc);
        } catch (NoSuchAlgorithmException e) {
            Log.e("#######", e.getMessage(), e);
        } catch (NoSuchPaddingException e) {
            Log.e("#######", e.getMessage(), e);
        } catch (InvalidKeyException e) {
            Log.e("#######", e.getMessage(), e);
        } catch (BadPaddingException e) {
            Log.e("#######", e.getMessage(), e);
        } catch (IllegalBlockSizeException e) {
            Log.e("#######", e.getMessage(), e);
        }
        return plain;
    }

}
