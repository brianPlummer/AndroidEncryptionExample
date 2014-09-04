package com.codemonkeylabs.encryptionsexample;

import com.codemonkeylabs.encryptionexample.app.AESEncryptDecrypt;
import com.codemonkeylabs.encryptionexample.app.RSAEncryptDecrypt;

import org.apache.commons.io.IOUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

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
        testText = IOUtils.toString(getClass().getResourceAsStream("/moby_dick.txt"));
    }

    @After
    public void tearDown() throws Exception
    {
        testText = null;
    }

    @Test
    public void testAESEncryption()
    {
        AESEncryptDecrypt aesEncryptDecrypt = new AESEncryptDecrypt();
        String encryptedString = aesEncryptDecrypt.encrypt(testText,AESEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.getBytes());
        String unencryptedString = aesEncryptDecrypt.decrypt(encryptedString,AESEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.getBytes());
        assertTrue(unencryptedString.startsWith("All this while Tashtego, Daggoo, and Queequeg"));
    }

    @Test
    public void testRSAandAESEncryption()
    {
        AESEncryptDecrypt aesEncryptDecrypt = new AESEncryptDecrypt();
        RSAEncryptDecrypt rsaEncryptDecrypt = new RSAEncryptDecrypt();
        String encryptedString = aesEncryptDecrypt.encrypt(testText,AESEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.getBytes());
        byte[] encryptedAESKey = rsaEncryptDecrypt.encrypt(AESEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.getBytes());
        byte[] unencryptedAESKey = rsaEncryptDecrypt.decrypt(encryptedAESKey);
        String unencryptedString = aesEncryptDecrypt.decrypt(encryptedString,unencryptedAESKey);
        assertTrue(unencryptedString.startsWith("All this while Tashtego, Daggoo, and Queequeg"));
    }
}
