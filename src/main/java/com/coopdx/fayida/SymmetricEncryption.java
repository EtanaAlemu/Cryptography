package com.coopdx.fayida;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class SymmetricEncryption {

    /* Encryption Method */
    public static String encryptAesCbc(String strToEncrypt, String SECRET_KEY, String SALTVALUE)
    {
        try
        {
            /* Declare a byte array. */
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            /* Create factory for secret keys. */
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            /* PBEKeySpec class implements KeySpec interface. */
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALTVALUE.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            /* Retruns encrypted value. */
            return Base64.getEncoder()
                    .encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
        }
        catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e)
        {
            System.out.println("Error occured during encryption: " + e.toString());
        }
        return null;
    }

    /* Decryption Method */
    public static String decryptAesCbc(String strToDecrypt, String SECRET_KEY, String SALTVALUE)
    {
        try
        {
            /* Declare a byte array. */
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            /* Create factory for secret keys. */
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            /* PBEKeySpec class implements KeySpec interface. */
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALTVALUE.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            /* Retruns decrypted value. */
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        }
        catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e)
        {
            System.out.println("Error occured during decryption: " + e.toString());
        }
        return null;
    }

    private static final SecureRandom secureRandom = new SecureRandom();
    private final static int GCM_IV_LENGTH = 12;
    /**
     * Encrypt a plaintext with given key.
     *
     * @param plaintext      to encrypt (utf-8 encoding will be used)
     * @param SECRET_KEY      to encrypt, must be AES type, see {@link SecretKeySpec}
//     * @param associatedData optional, additional (public) data to verify on decryption with GCM auth tag
     * @return encrypted message
     * @throws Exception if anything goes wrong
     */
    private static byte[] encryptAesGcm(String plaintext, String SECRET_KEY, String SALTVALUE) throws Exception {

        /* Create factory for secret keys. */
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        /* PBEKeySpec class implements KeySpec interface. */
        KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALTVALUE.getBytes(), 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

        byte[] iv = new byte[GCM_IV_LENGTH]; //NEVER REUSE THIS IV WITH SAME KEY
        secureRandom.nextBytes(iv);
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv); //128 bit auth tag length
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

//        if (associatedData != null) {
//            cipher.updateAAD(associatedData);
//        }

        byte[] cipherText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);
        return byteBuffer.array();
    }

    /**
//     * Decrypts encrypted message (see {@link #(String, String, String, byte[])}).
     *
     * @param cipherMessage  iv with ciphertext
     * @param SECRET_KEY      used to decrypt
//     * @param associatedData optional, additional (public) data to verify on decryption with GCM auth tag
     * @return original plaintext
     * @throws Exception if anything goes wrong
     */
    private static String decryptAesGcm(byte[] cipherMessage, String SECRET_KEY, String SALTVALUE) throws Exception {

        /* Create factory for secret keys. */
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        /* PBEKeySpec class implements KeySpec interface. */
        KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALTVALUE.getBytes(), 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        //use first 12 bytes for iv
        AlgorithmParameterSpec gcmIv = new GCMParameterSpec(128, cipherMessage, 0, GCM_IV_LENGTH);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmIv);

//        if (associatedData != null) {
//            cipher.updateAAD(associatedData);
//        }
        //use everything from 12 bytes on as ciphertext
        byte[] plainText = cipher.doFinal(cipherMessage, GCM_IV_LENGTH, cipherMessage.length - GCM_IV_LENGTH);

        return new String(plainText, StandardCharsets.UTF_8);
    }
    /* Driver Code */
    public static void main(String[] args) throws Exception {
        /* Call the encrypt() method and store result of encryption. */
        String encryptedval = encryptAesCbc(args[0],args[1],args[2]);
        /* Call the decrypt() method and store result of decryption. */
        String decryptedval = decryptAesCbc(encryptedval,args[1],args[2]);
        /* Display the original message, encrypted message and decrypted message on the console. */
        System.out.println("Original value: " + args[0]);
        System.out.println("Encrypted CBC value: " + encryptedval);
        System.out.println("Decrypted CBC value: " + decryptedval);

        byte[] cipherText = encryptAesGcm(args[0], args[1], args[2]);
        String decrypted = decryptAesGcm(cipherText, args[1], args[2]);

        System.out.println("Encrypted GCM value: " + cipherText);
        System.out.println("Decrypted GCM value: " + decrypted);
    }
}