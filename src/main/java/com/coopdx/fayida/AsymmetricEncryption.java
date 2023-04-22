package com.coopdx.fayida;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class AsymmetricEncryption {
//    private static String encrypt(String plaintext, RSAPublicKey pubkey) {
    private static String encrypt(String plaintext, String pubkey) {
        try {

            // Base64 decoding to byte array
            byte[] publicKeyByteServer = Base64.getDecoder().decode(pubkey);
            // generate the publicKey
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKeyServer = (PublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyByteServer));
            System.out.println("publicKeyServer: " + publicKeyServer);
// --- encrypt given algorithm string
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, publicKeyServer);
            byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            return Base64.getEncoder()
                    .encodeToString(ct);
        } catch (InvalidKeyException |InvalidKeySpecException| NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException |
                 NoSuchPaddingException e) {
            System.out.println("Error occured during encryption: " + e.toString());
        }
        return null;
    }

    private static String decrypt(String strToDecrypt, String privkey) {
        try {

            // Base64 decoding to byte array
            byte[] privateKeyByteServer = Base64.getDecoder().decode(privkey);
            // generate the publicKey
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKeyServer = (PrivateKey) keyFactory.generatePrivate(new X509EncodedKeySpec(privateKeyByteServer));
            System.out.println("privateKeyServer: " + privateKeyServer);
            // --- decrypt given OAEPParameterSpec
            Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/OAEPPadding");
            OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1",
                    new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT);
            oaepFromInit.init(Cipher.DECRYPT_MODE, privateKeyServer, oaepParams);
            byte[] ct = Base64.getDecoder().decode(strToDecrypt);
            byte[] pt = oaepFromInit.doFinal(ct);
            return new String(pt, StandardCharsets.UTF_8);

        } catch (InvalidAlgorithmParameterException  |InvalidKeySpecException| InvalidKeyException | NoSuchAlgorithmException |
                 BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            System.out.println("Error occured during encryption: " + e.toString());
        }
        return null;
    }


    public static void main(String[] args) throws Exception {


        System.out.println("Convert RSA public key into a string an dvice versa");
        // generate a RSA key pair
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(2048, new SecureRandom());
        KeyPair keyPair = keygen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
//        System.out.println("publicKey: " + publicKey);
//        System.out.println("privateKey: " + privateKey);
        // get encoded form (byte array)
        byte[] publicKeyByte = publicKey.getEncoded();
        byte[] privateKeyByte = privateKey.getEncoded();
        // Base64 encoded string
        String publicKeyString = Base64.getEncoder().encodeToString(publicKeyByte);
        String privateKeyString = Base64.getEncoder().encodeToString(privateKeyByte);
//        System.out.println("publicKeyString: " + publicKeyString);
//        System.out.println("privateKeyString: " + privateKeyString);
        // ... transport to server
        // Base64 decoding to byte array
        byte[] publicKeyByteServer = Base64.getDecoder().decode(publicKeyString);
        byte[] privateKeyByteServer = Base64.getDecoder().decode(privateKeyString);
        // generate the publicKey
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKeyServer = (PublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyByteServer));
//        System.out.println("publicKeyServer: " + publicKeyServer);
//        PrivateKey privateKeyServer = (PrivateKey) keyFactory.generatePrivate(new X509EncodedKeySpec(privateKeyByteServer));
//        System.out.println("privateKeyServer: " + privateKeyServer);

        // --- we need a key pair to test encryption/decryption
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
//        kpg.initialize(1024); // speedy generation, but not secure anymore
//        KeyPair kp = kpg.generateKeyPair();
//        RSAPublicKey pubkey = (RSAPublicKey) kp.getPublic();
//        RSAPrivateKey privkey = (RSAPrivateKey) kp.getPrivate();

        /* Call the encrypt() method and store result of encryption. */
        String encryptedval = encrypt(args[0],  publicKeyString);
        /* Call the decrypt() method and store result of decryption. */
        String decryptedval = decrypt(encryptedval,  privateKeyString);
        /* Display the original message, encrypted message and decrypted message on the console. */
        System.out.println("Original value: " + args[0]);
        System.out.println("Encrypted ECB value: " + encryptedval);
        System.out.println("Decrypted ECB value: " + decryptedval);
        String str = "gLtw5Nr9nEVS1kHZBqFTrjO3tx+rI50ctkodWa8Pdrcw+z+jOBjBmGIMgmNR10e2Szjjm9doDY2a+PLobVKNLhrGONpCXQNAfobONtojjDxVWKRltFgnxR14WSfcNRnyAd84HG3Qp6jcrxccpGEJXv5K3+bNZIE4DNTLBMI+TQ4=";

    }
}
