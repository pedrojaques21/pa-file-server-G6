import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Arrays;

public class Encryption {

    /**
     * Generates a random secret key pair using the RSA algorithm with a key size of 2048 bits
     *
     * @return a randomly generated secret key
     *
     * @throws Exception when the key generation fails
     */
    public static KeyPair generateKeyPair ( ) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance ( "RSA" );
        keyPairGenerator.initialize ( 2048 );
        return keyPairGenerator.generateKeyPair ( );
    }

    /**
     * Encrypts a message using the RSA algorithm with the provided public key and
     * returns the encrypted message as an array of bytes
     *
     * @param message  the message to be encrypted
     * @param publicKey the public key used to encrypt the message
     *
     * @return the encrypted message as an array of bytes
     *
     * @throws Exception when the encryption fails
     */
    public static byte[] encryptRSA ( byte[] message , Key publicKey ) throws Exception {
        Cipher cipher = Cipher.getInstance ( "RSA" );
        cipher.init ( Cipher.ENCRYPT_MODE , publicKey );
        return cipher.doFinal ( message );
    }

    /**
     * Decrypts a message using the RSA algorithm with the provided private key and
     * returns the decrypted message as an array of bytes
     *
     * @param message  the message to be decrypted
     * @param privateKey the private key used to decrypt the message
     *
     * @return the decrypted message as an array of bytes
     *
     * @throws Exception when the decryption fails
     */
    public static byte[] decryptRSA ( byte[] message , Key privateKey ) throws Exception {
        Cipher cipher = Cipher.getInstance ( "RSA" );
        cipher.init ( Cipher.DECRYPT_MODE , privateKey );
        return cipher.doFinal ( message );
    }

    /**
     * Encrypts a text using AES in CBC (Cipher Block Chaining) mode.
     * The initialization vector is created with a random value with the same length of the block size,
     *
     * @param message   the message to be encrypted
     * @param secretKey the secret key used to encrypt the message
     * @param algorithm AES, DES or 3DES
     *
     * @return the encrypted message as an array of bytes
     *
     * @throws Exception when the encryption fails
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
     * Decrypts a text using AES in CBC (Cipher Block Chaining) mode.
     *
     * @param Message   the message to be decrypted
     * @param secretKey secretKey the secret key used to decrypt the message
     * @param algorithm AES, DES or 3DES
     *
     * @return the decrypted message as an array of bytes
     *
     * @throws Exception when the decryption fails
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


    /**
     * Returns the key size in bits for the specified algorithm
     *
     * @param algorithm the algorithm to be used
     *
     * @return the key size in bits for the specified algorithm
     */
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