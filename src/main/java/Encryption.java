import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class Encryption {

    /**
     * Generates a random secret key pair using the RSA algorithm with a key size of 2048 bits
     *
     * @return a randomly generated secret key
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
     * @return the encrypted message as an array of bytes
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
     * @return the decrypted message as an array of bytes
     * @throws Exception when the decryption fails
     */
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
    public static byte[] encryptMessage(byte[] message , byte[] secretKey, String algorithm ) throws Exception {
        byte[] secretKeyPadded = ByteBuffer.allocate ( keySize(algorithm)/8 ).put ( secretKey ).array ( );
        SecretKeySpec secreteKeySpec = new SecretKeySpec ( secretKeyPadded , algorithm );
        Cipher cipher = Cipher.getInstance ( algorithm + "/ECB/PKCS5Padding" );
        cipher.init ( Cipher.ENCRYPT_MODE , secreteKeySpec );
        return cipher.doFinal ( message );
    }

    /**
     * @param message   the message to be decrypted with AES256 Algorithm
     * @param secretKey the secret key used to decrypt the message
     *
     * @return the decrypted message as an array of bytes
     *
     * @throws Exception when the encryption fails
     */
    public static byte[] decryptMessage(byte[] message , byte[] secretKey, String algorithm  ) throws Exception {
        byte[] secretKeyPadded = ByteBuffer.allocate ( keySize(algorithm)/8 ).put ( secretKey ).array ( );
        SecretKeySpec secreteKeySpec = new SecretKeySpec ( secretKeyPadded , algorithm );
        Cipher cipher = Cipher.getInstance ( algorithm + "/ECB/PKCS5Padding" );
        cipher.init ( Cipher.DECRYPT_MODE , secreteKeySpec );
        return cipher.doFinal ( message );
    }

    // KeySize assigned for each algorithm
    private static int keySize(String algorithm) {
        if (algorithm.equals("DESede")) {
            return 24;
        } else if (algorithm.equals("DES")) {
            return 64;
        } else {    // "AES"
            return 256;
        }
    }

}