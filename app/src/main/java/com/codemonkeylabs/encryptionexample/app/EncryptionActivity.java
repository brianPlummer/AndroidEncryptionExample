package com.codemonkeylabs.encryptionexample.app;

import android.app.Activity;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;


public class EncryptionActivity extends Activity {

    private Button encryptButton = null, decryptButton = null, clearButton = null;
    private EditText decryptedText = null, encryptedText = null, originalText = null ;

    private AESEncryptDecrypt encryptDecrypt;
    private RSAEncryptDecrypt rsaEncryptDecrypt;

    private byte[] encryptedAESKey = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_encryption);
        wireUI();
        this.encryptDecrypt = new AESEncryptDecrypt();
        this.rsaEncryptDecrypt = new RSAEncryptDecrypt();
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.encryption, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }


    private void wireUI(){

        this.originalText = (EditText)findViewById(R.id.originalText);
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
        byte[] decryptedAESKey = this.rsaEncryptDecrypt.decrypt(this.encryptedAESKey);

        if(encText!=null && encText.trim().length()>0)
            this.decryptedText.setText(this.encryptDecrypt.decrypt(encText,decryptedAESKey));
    }

    private void clearButton(){
        this.originalText.setText(getString(R.string.default_hint));
        this.encryptedText.setText(" ");
        this.decryptedText.setText(" ");
        this.encryptedAESKey = null;
    }

    private void encryptButton(){
        String original = this.originalText.getText().toString();
        if(original!=null && original.trim().length()>0)
            this.encryptedText.setText(this.encryptDecrypt.encrypt(original,AESEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.getBytes()));

        this.encryptedAESKey = this.rsaEncryptDecrypt.encrypt(AESEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.getBytes());
    }


}
