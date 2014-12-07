package com.codemonkeylabs.encryptionsexample;

import com.codemonkeylabs.encryptionexample.app.AESEncryptDecrypt;
import com.codemonkeylabs.encryptionexample.app.RSAEncryptDecrypt;
import com.codemonkeylabs.encryptionexample.app.Util;

import org.apache.commons.io.IOUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.util.Arrays;

/**
 * Created by brianplummer on 9/2/14.
 */
@RunWith(JUnit4.class)
public class EncryptionTest
{

    private String testText = null;

    @Before
    public void setUp() throws IOException
    {
        File mobyDickFile = new File("src/test/resources/moby_dick.txt");
        FileInputStream fis = new FileInputStream(mobyDickFile);
        testText = IOUtils.toString(fis);
    }

    @After
    public void tearDown() throws Exception
    {
        testText = null;
    }


    @Test
    public void testAESEncryptionCBC() throws UnsupportedEncodingException
    {

        ByteArrayInputStream plainTextInputStream = new ByteArrayInputStream(testText.getBytes("UTF-8"));
        ByteArrayOutputStream encOutputStream = new ByteArrayOutputStream(1024 * 100);

        byte[] iv = AESEncryptDecrypt.aesEncrypt(plainTextInputStream,
                AESEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.toCharArray(),
                AESEncryptDecrypt.AESCipherType.AES_CBC_PKCS5PADDING,
                encOutputStream);


        ByteArrayInputStream encInputStream = new ByteArrayInputStream(encOutputStream.toByteArray());
        ByteArrayOutputStream plainTextOutputStream = new ByteArrayOutputStream(1024 * 100);

        AESEncryptDecrypt.aesDecrypt(encInputStream,
                AESEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.toCharArray(),
                iv,
                AESEncryptDecrypt.AESCipherType.AES_CBC_PKCS5PADDING,
                plainTextOutputStream);


        String unencryptedString = new String(plainTextOutputStream.toByteArray(),"UTF-8");

        assertTrue(unencryptedString.startsWith("All this while Tashtego, Daggoo, and Queequeg"));
    }


    @Test
    public void testAESEncryptionCTR() throws UnsupportedEncodingException
    {
        ByteArrayInputStream plainTextInputStream = new ByteArrayInputStream(testText.getBytes("UTF-8"));
        ByteArrayOutputStream encOutputStream = new ByteArrayOutputStream(1024 * 100);

        byte[] iv = AESEncryptDecrypt.aesEncrypt(plainTextInputStream,
                AESEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.toCharArray(),
                AESEncryptDecrypt.AESCipherType.AES_CIPHER_CTR_NOPADDING,
                encOutputStream);


        ByteArrayInputStream encInputStream = new ByteArrayInputStream(encOutputStream.toByteArray());
        ByteArrayOutputStream plainTextOutputStream = new ByteArrayOutputStream(1024 * 100);

        AESEncryptDecrypt.aesDecrypt(encInputStream,
                AESEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.toCharArray(),
                iv,
                AESEncryptDecrypt.AESCipherType.AES_CIPHER_CTR_NOPADDING,
                plainTextOutputStream);


        String unencryptedString = new String(plainTextOutputStream.toByteArray(),"UTF-8");

        assertTrue(unencryptedString.startsWith("All this while Tashtego, Daggoo, and Queequeg"));
    }


    @Test
    public void testAESEncryptionECB() throws UnsupportedEncodingException
    {
        ByteArrayInputStream plainTextInputStream = new ByteArrayInputStream(testText.getBytes("UTF-8"));
        ByteArrayOutputStream encOutputStream = new ByteArrayOutputStream(1024 * 100);

        byte[] iv = AESEncryptDecrypt.aesEncrypt(plainTextInputStream,
                AESEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.toCharArray(),
                AESEncryptDecrypt.AESCipherType.AES_CIPHER_ECB_PKCS5PADDING,
                encOutputStream);


        ByteArrayInputStream encInputStream = new ByteArrayInputStream(encOutputStream.toByteArray());
        ByteArrayOutputStream plainTextOutputStream = new ByteArrayOutputStream(1024 * 100);

        AESEncryptDecrypt.aesDecrypt(encInputStream,
                AESEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.toCharArray(),
                iv,
                AESEncryptDecrypt.AESCipherType.AES_CIPHER_ECB_PKCS5PADDING,
                plainTextOutputStream);


        String unencryptedString = new String(plainTextOutputStream.toByteArray(),"UTF-8");

        assertTrue(unencryptedString.startsWith("All this while Tashtego, Daggoo, and Queequeg"));
    }

    @Test
    public void testRSAandAESEncryption() throws UnsupportedEncodingException
    {

        KeyPair rsaKeyPair = RSAEncryptDecrypt.generateRSAKey();


        ByteArrayInputStream plainTextInputStream = new ByteArrayInputStream(testText.getBytes("UTF-8"));
        ByteArrayOutputStream encOutputStream = new ByteArrayOutputStream(1024 * 100);

        byte[] iv = AESEncryptDecrypt.aesEncrypt(plainTextInputStream,
                AESEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.toCharArray(),
                AESEncryptDecrypt.AESCipherType.AES_CBC_PKCS5PADDING,
                encOutputStream);


        byte[] combined = Util.concat(AESEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.getBytes(),
                iv);

        byte[] encryptedAESKey = RSAEncryptDecrypt.encryptRSA(combined, rsaKeyPair.getPublic());

        byte[] unencryptedAESKey = RSAEncryptDecrypt.decryptRSA(encryptedAESKey, rsaKeyPair.getPrivate());

        byte[] aesKey = Arrays.copyOfRange(unencryptedAESKey, 0, 32);
        byte[] ivs = Arrays.copyOfRange(unencryptedAESKey, 32, 48);

        ByteArrayInputStream encInputStream = new ByteArrayInputStream(encOutputStream.toByteArray());
        ByteArrayOutputStream plainTextOutputStream = new ByteArrayOutputStream(1024 * 100);

        AESEncryptDecrypt.aesDecrypt(encInputStream,
                new String(aesKey, "UTF-8").toCharArray(),
                ivs,
                AESEncryptDecrypt.AESCipherType.AES_CBC_PKCS5PADDING,
                plainTextOutputStream);

        String unencryptedString = new String(plainTextOutputStream.toByteArray(),"UTF-8");

        assertTrue(unencryptedString.startsWith("All this while Tashtego, Daggoo, and Queequeg"));
    }

}
