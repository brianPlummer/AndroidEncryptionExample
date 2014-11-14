package com.codemonkeylabs.encryptionexample.app;



import org.apache.commons.io.IOUtils;
import org.ow2.util.base64.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by brianplummer on 4/29/14.
 */
public class AESEncryptDecrypt {

    //16 byte key....other sizes allowed.....getBytes defaults to utf-8
    public static final String NOT_SECRET_ENCRYPTION_KEY = "1234567812345678";
    //Must be 16 bytes long....getBytes defaults to utf-8
    public static final String IVS = "1234567812345678";

    public static final String AES_CIPHER = "AES/CTR/NoPadding";
    public static final String AES = "AES";

    public String encrypt(String inData, byte[] key, byte[] ivs)
    {
        byte[] encryptedData = aesEncrypt(inData.getBytes(),
                key,
                ivs);
        return new String(Base64.encode(encryptedData));
    }

    public String decrypt(String inData, byte[] key, byte[] ivs)
    {
        byte[] decryptData = aesDecrypt(Base64.decode(inData.toCharArray()),
                key,
                ivs);
        return new String(decryptData);
    }

    public static final int BYTE_BUFFER_SIZE = 1024 * 100;//100k

    public static byte[] aesEncrypt(byte[] data, byte[] key, byte[] ivs)
    {
        CipherOutputStream cos = null;
        ByteArrayOutputStream bos = null;
        try
        {
            Cipher cipher = Cipher.getInstance(AES_CIPHER);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, AES);
            IvParameterSpec ivps = new IvParameterSpec(ivs);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivps);

            bos = new ByteArrayOutputStream(BYTE_BUFFER_SIZE);
            cos = new CipherOutputStream(bos,cipher);
            ByteArrayInputStream bis = new ByteArrayInputStream(data);

            IOUtils.copy(bis, cos);
            return bos.toByteArray();
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
        finally
        {
            if(cos != null)
                try
                {
                    cos.close();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
        }
    }

    public static byte[] aesDecrypt(byte[] data, byte[] key, byte[] ivs)
    {
        byte[] retData = null;
        CipherInputStream cis = null;
        try
        {
            Cipher cipher = Cipher.getInstance(AES_CIPHER);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, AES);
            IvParameterSpec ivps = new IvParameterSpec(ivs);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivps);

            ByteArrayInputStream bis = new ByteArrayInputStream(data);
            cis = new CipherInputStream(bis,cipher);
            ByteArrayOutputStream bos = new ByteArrayOutputStream(BYTE_BUFFER_SIZE);
            IOUtils.copy(cis,bos);
            retData =  bos.toByteArray();
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
        finally
        {
            if(cis != null)
                try
                {
                    cis.close();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
        }
        return retData;
    }

}
