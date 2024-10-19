package com.example.meltdownapp;

// This code is for RSA PKCS1



import android.app.Activity;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.text.InputType;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;


import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;



import java.security.cert.X509Certificate;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyStore.PrivateKeyEntry;
import javax.crypto.Cipher;
import java.security.KeyStore.Entry;
import java.util.Date;

public class MainActivity extends AppCompatActivity {
    // Updates :-
    // If not inside secure hardware terminate the authentication process
    // Where to attach IMEI ? (as Alias or embed it with Public Key or something else)
    // Lifecycle management


    // For Key Gen Purposes
    private static String alias = "UIDAIKeyAlias";
    private String data_to_encrypt; // blob data to encrypt
    private String encryptedText = "";
    private String decryptedText = "";
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private String Base64certificateChain; // store encoded base64 certificate chain
    private int certChainLength;
    private int validity;
    private X509Certificate[] certChain;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // whenever app starts :-
//        generateKeyPair();
//        LogPublicKey("UIDAIKeyAlias");
//        encrypt();
//        decrypt();



        Button button1 = findViewById(R.id.button1); // find the button by ID in resource folder
        Button button2 = findViewById(R.id.button2);
        Button button3 = findViewById(R.id.button3);
        Button button4 = findViewById(R.id.button4);
        Button button5 = findViewById(R.id.button5);

        button1.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // The following is to take input from user
                final EditText input1 = new EditText(MainActivity.this);
                final EditText input2 = new EditText(MainActivity.this);
                input1.setInputType(InputType.TYPE_CLASS_TEXT);
                input2.setInputType(InputType.TYPE_CLASS_TEXT);
                input1.setHint("Enter Alias (Give any unique name to your keys)");
                input2.setHint("Enter the time in milliseconds for validity of keys");
                LinearLayout layout = new LinearLayout(MainActivity.this);
                layout.setOrientation(LinearLayout.VERTICAL); // Vertically align the EditTexts
                layout.addView(input1);
                layout.addView(input2);


                AlertDialog.Builder inputDialogBuilder = new AlertDialog.Builder(MainActivity.this);
                inputDialogBuilder.setTitle("Enter Inputs to Generate Key pair using RSA");
                inputDialogBuilder.setView(layout);

                inputDialogBuilder.setPositiveButton("OK", (dialog, which) -> {
                    alias = input1.getText().toString(); // always updating to the current alias
                    validity = Integer.parseInt(input2.getText().toString());

                    boolean temp = generateKeyPair(alias, validity); // Generate the Key Pair (temp is true if the key is inside the secure hardware)
                    String publicKeyString = getPublicKey(alias); // Get Public Key

                    AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);

                    if (temp && publicKeyString != null) { // temp is true if the key is inside the secure hardware
                        builder.setMessage("Key Pair Successfully generated and Inside Secure Hardware!\n\n" +
                                        "Public Key [Base64]: " + publicKeyString)
                                .setTitle("RSA Key Generation");
                    } else {
                        builder.setMessage("Key Pair Generation Failed!")
                                .setTitle("RSA Key Generation");
                    }
                    builder.setPositiveButton("OK", (dialog1, id) -> {
                        dialog1.dismiss(); // Dismiss the dialog
                    });
                    AlertDialog dialog2 = builder.create();
                    dialog2.show();
                });

                inputDialogBuilder.setNegativeButton("Cancel", (dialog, which) -> dialog.cancel());

                // Create and show the input dialog
                AlertDialog inputDialog = inputDialogBuilder.create();
                inputDialog.show();
            }
        });


        button2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // for Taking Input from user
                final EditText input = new EditText(MainActivity.this);
                input.setInputType(InputType.TYPE_CLASS_TEXT); // Set input type (text)
                AlertDialog.Builder inputDialogBuilder = new AlertDialog.Builder(MainActivity.this);
                inputDialogBuilder.setTitle("Enter Alias (Give any unique name to your keys)");
                inputDialogBuilder.setView(input); // Set the EditText as the dialog's view

                inputDialogBuilder.setPositiveButton("OK", (dialog, which) -> {
                    String alias = input.getText().toString(); // Get the user input

                    // Now show the public key dialog
                    String publicKeyString = getPublicKey(alias);
                    AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                    if (publicKeyString != null) {
                        builder.setMessage("[Base64] : " + publicKeyString)
                                .setTitle("Public Key");
                    } else {
                        builder.setMessage("Alias Not Found!")
                                .setTitle("RSA Key Generation");
                    }

                    builder.setPositiveButton("OK", (dialog1, id) -> {
                        dialog1.dismiss(); // Dismiss the dialog
                    });

                    AlertDialog dialog2 = builder.create();
                    dialog2.show();
                });
                inputDialogBuilder.setNegativeButton("Cancel", (dialog, which) -> dialog.cancel());

                // Create and show the input dialog
                AlertDialog inputDialog = inputDialogBuilder.create();
                inputDialog.show();
            }
        });

        button3.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // for Taking Input from user
                final EditText input = new EditText(MainActivity.this);
                input.setInputType(InputType.TYPE_CLASS_TEXT); // Set input type (text)
                AlertDialog.Builder inputDialogBuilder = new AlertDialog.Builder(MainActivity.this);
                inputDialogBuilder.setTitle("Enter String (Text) data to encrypt: ");
                inputDialogBuilder.setView(input); // Set the EditText as the dialog's view

                inputDialogBuilder.setPositiveButton("OK", (dialog, which) -> {
                    data_to_encrypt = input.getText().toString(); // Get the user input

                    // Now show the public key dialog
                    encryptedText = encrypt(data_to_encrypt);
                    decryptedText = decrypt(encryptedText);
                    AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                    if(encryptedText != null && decryptedText!= null){
                        builder.setMessage("Encrypted Text using Public Key: " + encryptedText + "\n\n\n" + "Decrypted Text using Private Key : " + decryptedText + "\n\n" + "Note that the encryption and decryption is taking place inside secure hardware TEE (Trusted Execution Environment)!")
                                .setTitle("Encrypt & Decrypt using RSA Key Pair with PKCS padding");
                    }
                    else if(encryptedText != null){ // if decryptedText is null
                        builder.setMessage("Sorry the key is expired !")
                                .setTitle("Encrypt & Decrypt using RSA Key Pair with PKCS padding");
                    }
                    else{
                        builder.setMessage("ERROR : Encrypted Text is null ? how ?")
                                .setTitle("Encrypt & Decrypt using RSA Key Pair with PKCS padding");
                    }
                    builder.setPositiveButton("OK", (dialog1, id) -> {
                        dialog1.dismiss(); // Dismiss the dialog
                    });

                    AlertDialog dialog2 = builder.create();
                    dialog2.show();
                });
                inputDialogBuilder.setNegativeButton("Cancel", (dialog, which) -> dialog.cancel());

                // Create and show the input dialog
                AlertDialog inputDialog = inputDialogBuilder.create();
                inputDialog.show();
            }
        });

        button4.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    getAttestationCertificate();
                    AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                    builder.setTitle("Key Attestation Certificate");
                    builder.setMessage("[Base64]: " + Base64certificateChain);
                    builder.setPositiveButton("OK", (dialog, which) -> dialog.dismiss());

                    // Create and show the AlertDialog
                    builder.show();
                } catch (Exception e) {
                    AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                    builder.setTitle("Key Attestation Certificate");
                    builder.setMessage("[Base64]: " + Base64certificateChain);
                    builder.setPositiveButton("OK", (dialog, which) -> dialog.dismiss());
                    // Create and show the AlertDialog
                    builder.show();
                }
            }
        });



        button5.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v){
                showCertificateInfo();
            }
        });
    }










    private boolean generateKeyPair(String alias, int validity) {
        try {
            Date startDate = new Date(System.currentTimeMillis());
            Date endDate = new Date(System.currentTimeMillis() + validity);
            // create an object of Key generator from RSA Algo.
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(
                            alias,
                            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1) // PKCS1 Padding
                            .setKeySize(2048)
                            .setKeyValidityStart(startDate)
                            .setKeyValidityEnd(endDate)
                            .setAttestationChallenge(new byte[]{0x01, 0x02, 0x03})
                            .setUserAuthenticationRequired(false)
                            .build());


            KeyPair keyPair = keyPairGenerator.generateKeyPair(); // Generate a Key pair
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
            Log.i("KeyGen", "Key pair generated.");
            KeyFactory keyFactory = KeyFactory.getInstance(privateKey.getAlgorithm(), "AndroidKeyStore");
            KeyInfo keyInfo = (KeyInfo) keyFactory.getKeySpec(privateKey, KeyInfo.class);
            Log.i("KeyGen", "Is key inside Secure Hardware ? " + keyInfo.isInsideSecureHardware());
            return keyInfo.isInsideSecureHardware();
        } catch (Exception e) {
            Log.e("KeyGen", "Error generating key pair", e);
            return false;
        }
    }


    private void LogEncryptedText(String encryptedText){
        try{
            Log.i("Encryption", "Encrypted Text [Base64]: " + encryptedText);
        }catch (Exception e){
            Log.e("Encryption", "Unable to log ! Error : " + e);
        }
    }
    private void LogDecryptedText(String decryptedText){
        try{
            Log.i("Decryption", "Decrypted Text: " + decryptedText);
        }catch (Exception e){
            Log.e("Decryption", "Unable to log ! Error : " + e);
        }
    }
    public String encrypt(String data_to_encrypt){
        try{
            byte[] Text_Byte = data_to_encrypt.getBytes();
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(Text_Byte);
            encryptedText = Base64.encodeToString(encryptedBytes, Base64.DEFAULT);
            LogEncryptedText(encryptedText);
            return encryptedText;
        }
        catch (Exception e){
            Log.e("Encryption Cipher", "Error in Encryption Cipher: " + e);
            return (String)null;
        }
    }
    public String decrypt(String encryptedText){
        try{
            byte[] Text_Byte = Base64.decode(encryptedText, Base64.DEFAULT);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(Text_Byte);
            decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);
            LogDecryptedText(decryptedText);
            return decryptedText;
        }
        catch (Exception e){
            Log.e("Decryption Cipher", "Error in Decryption Cipher: " + e);
            return (String)null;
        }
    }


    private String getPublicKey(String Alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            KeyStore.Entry entry = keyStore.getEntry(Alias, null);
            if (entry instanceof KeyStore.PrivateKeyEntry) {
                if (keyStore.containsAlias(Alias)) {
                    PublicKey publicKey = keyStore.getCertificate(Alias).getPublicKey();
                    String publickeystring = Base64.encodeToString(publicKey.getEncoded(), Base64.DEFAULT);
                    return publickeystring;
                } else {
                    Log.e("Keystore", "KeyStore Can't find alias");
                    return (String)null;
                }
            } else {
                Log.e("Keystore", "KeyStore Can't find alias");
                return (String)null;
            }
        } catch (Exception e){
            Log.e("Public Key", "Something is wrong in getPublicKey()");
            return (String)null;
        }
    }
    public void getAttestationCertificate() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null); // Load the keystore

        Entry entry = keyStore.getEntry(alias, null);
        if (entry instanceof PrivateKeyEntry) {

            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) entry;

            certChain = new X509Certificate[] { (X509Certificate) privateKeyEntry.getCertificate() };

            certChainLength = certChain.length;
            X509Certificate attestationCert = certChain[0];

            byte[] attestationBytes = attestationCert.getEncoded();
            Base64certificateChain = Base64.encodeToString(attestationBytes, Base64.DEFAULT);
        }
    }

    private void showCertificateInfo() {
        try {
            // Retrieve the attestation certificate from the keystore
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            // Fetch the private key entry from the keystore
            Entry entry = keyStore.getEntry(alias, null);

            if (entry instanceof PrivateKeyEntry) {
                X509Certificate attestationCert = certChain[0];
                Date validityStart = attestationCert.getNotBefore();
                Date validityEnd = attestationCert.getNotAfter();
                String issuer = attestationCert.getIssuerX500Principal().getName();
                String subject = attestationCert.getSubjectX500Principal().getName();
                String signatureAlgorithm = attestationCert.getSigAlgName();
                String serialNumber = attestationCert.getSerialNumber().toString();


                AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                builder.setTitle("Certificate Details");
                builder.setMessage("Issuer: " + issuer + "\n" +
                        "Subject: " + subject + "\n" +
                        "Serial Number: " + serialNumber + "\n" +
                        "Signature Algorithm: " + signatureAlgorithm + "\n" +
                        "Validity Start Date: " + validityStart.toString() + "\n" +
                        "Validity End Date: " + validityEnd.toString());
                builder.setPositiveButton("OK", (dialog, which) -> dialog.dismiss());

                AlertDialog dialog = builder.create();
                dialog.show();
            }
        } catch (Exception e) {
            Log.e("Certificate Validity", "Error fetching certificate validity", e);
        }
    }
}
