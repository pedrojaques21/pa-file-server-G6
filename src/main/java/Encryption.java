import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;

public class Encryption {

    public static KeyPair generateKeyPair ( ) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance ( "RSA" );
        keyPairGenerator.initialize ( 2048 );
        return keyPairGenerator.generateKeyPair ( );
    }

    public static byte[] encryptRSA ( byte[] message , Key publicKey ) throws Exception {
        Cipher cipher = Cipher.getInstance ( "RSA" );
        cipher.init ( Cipher.ENCRYPT_MODE , publicKey );
        return cipher.doFinal ( message );
    }

    public static byte[] decryptRSA ( byte[] message , Key privateKey ) throws Exception {
        Cipher cipher = Cipher.getInstance ( "RSA" );
        cipher.init ( Cipher.DECRYPT_MODE , privateKey );
        return cipher.doFinal ( message );
    }

    /**
     * @param message   the message to be encrypted
     * @param secretKey the secret key used to encrypt the message
     *
     * @return the encrypted message as an array of bytes
     *
     * @throws Exception when the decryption fails
     */
    public static byte[] encryptMessage(byte[] message , byte[] secretKey, String algorithm, int keySize ) throws Exception {
        byte[] secretKeyPadded = ByteBuffer.allocate ( keySize/8 ).put ( secretKey ).array ( );
        SecretKeySpec secreteKeySpec = new SecretKeySpec ( secretKeyPadded , algorithm );
        Cipher cipher = Cipher.getInstance ( algorithm + "/ECB/PKCS5Padding" );
        cipher.init ( Cipher.ENCRYPT_MODE , secreteKeySpec );
        return cipher.doFinal ( message );
    }

    /**
     * @param message   the message to be decrypted with AES256 Algorithm
     * @param secretKey the secret key used to decrypt the message
     * @return the decrypted message as an array of bytes
     * @throws Exception when the encryption fails
     */
    public static byte[] decryptMessage(byte[] message , byte[] secretKey, String algorithm, int keySize  ) throws Exception {
        byte[] secretKeyPadded = ByteBuffer.allocate ( keySize/8 ).put ( secretKey ).array ( );
        SecretKeySpec secreteKeySpec = new SecretKeySpec ( secretKeyPadded , algorithm );
        Cipher cipher = Cipher.getInstance ( algorithm + "/ECB/PKCS5Padding" );
        cipher.init ( Cipher.DECRYPT_MODE , secreteKeySpec );
        return cipher.doFinal ( message );
    }

//    /**
//     *
//     * @param message   the message to be encrypted with DES algorithm
//     * @param secretKey the secret key used to decrypt the message
//     * @return the decrypted message as an array of bytes
//     * @throws Exception when the encryption fails
//     */
//    public static byte[] encryptMessageDES(byte[] message, byte[] secretKey) throws Exception {
//        byte[] secretKeyPadded = Arrays.copyOf(secretKey, 8);
//        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyPadded, "DES");
//        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
//        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
//        return cipher.doFinal(message);
//    }
//
//    public static byte[] decryptMessageDES(byte[] encryptedMessage, byte[] secretKey) throws Exception {
//        byte[] secretKeyPadded = Arrays.copyOf(secretKey, 8);
//        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyPadded, "DES");
//        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
//        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
//        return cipher.doFinal(encryptedMessage);
//    }
//
//    public static byte[] encryptMessage3DES(byte[] message, byte[] secretKey) throws Exception {
//        byte[] secretKeyPadded = Arrays.copyOf(secretKey, 24);
//        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyPadded, "DESede");
//        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
//        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
//        return cipher.doFinal(message);
//    }
//
//    public static byte[] decryptMessage3DES(byte[] encryptedMessage, byte[] secretKey) throws Exception {
//        byte[] secretKeyPadded = Arrays.copyOf(secretKey, 24);
//        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyPadded, "DESede");
//        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
//        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
//        return cipher.doFinal(encryptedMessage);
//    }

}