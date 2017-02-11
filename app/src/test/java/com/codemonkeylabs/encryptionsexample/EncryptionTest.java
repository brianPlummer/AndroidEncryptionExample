package com.codemonkeylabs.encryptionsexample;

import com.codemonkeylabs.encryptionexample.app.AESEncryptDecrypt;
import com.codemonkeylabs.encryptionexample.app.RSAEncryptDecrypt;
import com.codemonkeylabs.encryptionexample.app.Util;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.Assert.assertTrue;

public class EncryptionTest
{
    private String testText = null;

    @Before
    public void setUp() throws Exception
    {

        File file = new File("./","/src/test/res/moby_dick.txt");
        FileInputStream fis = new FileInputStream(file);
        testText = IOUtils.toString(fis);
        // specify bouncyCastle provider for unit test runtime
        AESEncryptDecrypt.setProvider(new BouncyCastleProvider(), "BC");
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
    public void testAESEncryptionCBCPadding7() throws UnsupportedEncodingException
    {

        ByteArrayInputStream plainTextInputStream = new ByteArrayInputStream(testText.getBytes("UTF-8"));
        ByteArrayOutputStream encOutputStream = new ByteArrayOutputStream(1024 * 100);

        byte[] iv = AESEncryptDecrypt.aesEncrypt(plainTextInputStream,
                AESEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.toCharArray(),
                AESEncryptDecrypt.AESCipherType.AES_CBC_PKCS7Padding,
                encOutputStream);


        ByteArrayInputStream encInputStream = new ByteArrayInputStream(encOutputStream.toByteArray());
        ByteArrayOutputStream plainTextOutputStream = new ByteArrayOutputStream(1024 * 100);

        AESEncryptDecrypt.aesDecrypt(encInputStream,
                AESEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.toCharArray(),
                iv,
                AESEncryptDecrypt.AESCipherType.AES_CBC_PKCS7Padding,
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

        //generate RSA key pair
        KeyPair rsaKeyPair = RSAEncryptDecrypt.generateRSAKey();

        //set up streams for plain text input and encrypted output
        ByteArrayInputStream plainTextInputStream = new ByteArrayInputStream(testText.getBytes("UTF-8"));
        ByteArrayOutputStream encOutputStream = new ByteArrayOutputStream(1024 * 100);

        //aes encrypt the data
        byte[] iv = AESEncryptDecrypt.aesEncrypt(plainTextInputStream,
                AESEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.toCharArray(),
                AESEncryptDecrypt.AESCipherType.AES_CBC_PKCS5PADDING,
                encOutputStream);

        //combines the aes key and iv so we can encrypt that and potentially transmit/store that with
        //the data
        byte[] combined = Util.concat(AESEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.getBytes(),
                iv);

        //rsa encrypt the combined aes/iv
        byte[] encryptedAESKey = RSAEncryptDecrypt.encryptRSA(combined, rsaKeyPair.getPublic());

        //decrypt the combined aes/iv
        byte[] unencryptedAESKey = RSAEncryptDecrypt.decryptRSA(encryptedAESKey, rsaKeyPair.getPrivate());

        //pull out the aes key and iv from the decrypted combined array
        byte[] aesKey = Arrays.copyOfRange(unencryptedAESKey, 0, 32);
        byte[] ivs = Arrays.copyOfRange(unencryptedAESKey, 32, 48);

        //set up the streams for the encrypted input and the plain text output
        ByteArrayInputStream encInputStream = new ByteArrayInputStream(encOutputStream.toByteArray());
        ByteArrayOutputStream plainTextOutputStream = new ByteArrayOutputStream(1024 * 100);

        //decrypt encrypted text using the aes key and iv from combined value
        AESEncryptDecrypt.aesDecrypt(encInputStream,
                new String(aesKey, "UTF-8").toCharArray(),
                ivs,
                AESEncryptDecrypt.AESCipherType.AES_CBC_PKCS5PADDING,
                plainTextOutputStream);

        //get the plain text
        String unencryptedString = new String(plainTextOutputStream.toByteArray(),"UTF-8");

        //assert the value
        assertTrue(unencryptedString.startsWith("All this while Tashtego, Daggoo, and Queequeg"));
    }

}
