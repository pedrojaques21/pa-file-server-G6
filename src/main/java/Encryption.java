import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
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

//    /**
//     * @param message   the message to be encrypted
//     * @param secretKey the secret key used to encrypt the message
//     *
//     * @return the encrypted message as an array of bytes
//     *
//     * @throws Exception when the decryption fails
//     */
//    public static byte[] encryptMessage(byte[] message , byte[] secretKey, String algorithm ) throws Exception {
//        byte[] secretKeyPadded = ByteBuffer.allocate ( keySize(algorithm)/8 ).put ( secretKey ).array ( );
//        SecretKeySpec secreteKeySpec = new SecretKeySpec ( secretKeyPadded , algorithm );
//        Cipher cipher = Cipher.getInstance ( algorithm + "/ECB/PKCS5Padding" );
//        cipher.init ( Cipher.ENCRYPT_MODE , secreteKeySpec );
//        return cipher.doFinal ( message );
//    }


    /**
     * Encrypts a text using AES in CBC (Cipher Block Chaining) mode.
     * The initializatiom vector is created with a random value with the same length of the block size,
     * @param message   the message to be encrypted
     * @param secretKey the secret key used to encrypt the message
     * @param algorithm AES, DES or 3DES
     * @return          the encrypted message as an array of bytes
     * @throws Exception
     */
    public static byte[] encryptMessage(byte[] message, byte[] secretKey, String algorithm) throws Exception {
        byte[] secretKeyPadded = Arrays.copyOf(secretKey, keySize(algorithm) / 8);
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyPadded, algorithm);
        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
        byte[] iv = new byte[cipher.getBlockSize()];    // iv size = BlockSize
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encryptedMessage = cipher.doFinal(message);
        byte[] encryptedMessageWithIV = new byte[encryptedMessage.length + iv.length];
        System.arraycopy(iv, 0, encryptedMessageWithIV, 0, iv.length);
        System.arraycopy(encryptedMessage, 0, encryptedMessageWithIV, iv.length, encryptedMessage.length);
        return encryptedMessageWithIV;
    }

    /**
     * Dencrypts a text using AES in CBC (Cipher Block Chaining) mode.
     * @param Message   the message to be decrypted
     * @param secretKey secretKey the secret key used to decrypt the message
     * @param algorithm AES, DES or 3DES
     * @return          the decrypted message as an array of bytes
     * @throws Exception
     */
    public static byte[] decryptMessage(byte[] Message, byte[] secretKey, String algorithm) throws Exception {
        byte[] secretKeyPadded = ByteBuffer.allocate(keySize(algorithm) / 8).put(secretKey).array();
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyPadded, algorithm);
        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
        byte[] iv = Arrays.copyOfRange(Message, 0, cipher.getBlockSize());
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(Arrays.copyOfRange(Message, cipher.getBlockSize(), Message.length));
    }


    // KeySize assigned for each algorithm
    private static int keySize(String algorithm) {
        if (algorithm.equals("DESede")) {
            return 192;
        } else if (algorithm.equals("DES")) {
            return 64;
        } else {    // "AES"
            return 256;
        }
    }

}