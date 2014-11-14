package com.codemonkeylabs.encryptionexample.app;

import android.app.Activity;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import java.util.Arrays;

public class EncryptionActivity extends Activity {

    private Button encryptButton = null, decryptButton = null, clearButton = null;
    private EditText decryptedText = null, encryptedText = null, inputtedUnencryptedText = null ;

    //helper encryption classes
    private AESEncryptDecrypt aesEncryptDecrypt;
    private RSAEncryptDecrypt rsaEncryptDecrypt;

    //encrypted aes key and ivs combined
    private byte[] encryptedAESKey = null;

    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_encryption);
        wireUI();
        this.aesEncryptDecrypt = new AESEncryptDecrypt();
        this.rsaEncryptDecrypt = new RSAEncryptDecrypt();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu)
    {
        getMenuInflater().inflate(R.menu.encryption, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item)
    {
        int id = item.getItemId();
        if (id == R.id.action_settings)
        {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    /*
     *  wire the ui
     */
    private void wireUI()
    {
        this.inputtedUnencryptedText = (EditText)findViewById(R.id.inputtedUnencryptedText);
        this.encryptedText = (EditText)findViewById(R.id.encryptedText);
        this.decryptedText = (EditText)findViewById(R.id.decryptedText);

        this.encryptButton = (Button)findViewById(R.id.encryptButton);
        this.encryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                encryptButton();
            }
        });

        this.decryptButton = (Button)findViewById(R.id.decryptButton);
        this.decryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                decryptButton();
            }
        });

        this.clearButton = (Button)findViewById(R.id.clearButton);
        this.clearButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearButton();
            }
        });
    }

    private void decryptButton(){

        String encText = this.encryptedText.getText().toString();

        //sanity test on input from ui
        if(encText!=null && encText.trim().length()>0)
        {
            //decrypt the stored aes and ivs key
            byte[] decryptedAESKeyIVS = this.rsaEncryptDecrypt.decrypt(this.encryptedAESKey);

            byte[] aesKey = Arrays.copyOfRange(decryptedAESKeyIVS, 0, 16);
            byte[] ivs = Arrays.copyOfRange(decryptedAESKeyIVS, 16, 32);

            this.decryptedText.setText(this.aesEncryptDecrypt.decrypt(encText, aesKey, ivs));
        }
    }

    private void clearButton()
    {
        this.inputtedUnencryptedText.setText(getString(R.string.default_hint));
        this.encryptedText.setText(" ");
        this.decryptedText.setText(" ");
        this.encryptedAESKey = null;
    }

    private void encryptButton()
    {
        String inputtedUnencryptedText = this.inputtedUnencryptedText.getText().toString();

        //sanity check on input
        if(inputtedUnencryptedText!=null && inputtedUnencryptedText.trim().length()>0)
        {
            return;
        }

        //encrypt the inputted text using AES
        String encryptedText = aesEncryptDecrypt.encrypt(inputtedUnencryptedText,
                AESEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.getBytes(),
                AESEncryptDecrypt.IVS.getBytes());

        //set ui textview to encrypted base64 encoded value
        this.encryptedText.setText(encryptedText);


        //we combine the aes key and the ivs so we can encrypt it in one go
        byte[] combinedKey = concat(AESEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.getBytes(),
                AESEncryptDecrypt.IVS.getBytes());

        //we encrypt the combined key and store it for decryption later
        encryptedAESKey = this.rsaEncryptDecrypt.encrypt(combinedKey);
    }

    public byte[] concat(byte[] first, byte[] second){
        byte[] combined = new byte[first.length + second.length];
        System.arraycopy(first, 0, combined, 0, first.length);
        System.arraycopy(second, 0, combined, first.length, second.length);
        return combined;
    }

}
