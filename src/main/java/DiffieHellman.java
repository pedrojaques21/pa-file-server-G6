import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Diffie-Hellman key exchange algorithm.
 */
public class DiffieHellman {

    private static final BigInteger G = BigInteger.valueOf ( 3 );
    private static final BigInteger N = BigInteger.valueOf ( 1289971646 );
    private static final int NUM_BITS = 128;

    /**
     * Generates a private key of 128 bits using SHA1PRNG algorithm.
     *
     * @return private key.
     *
     * @throws NoSuchAlgorithmException if the algorithm is not found.
     */
    public static BigInteger generatePrivateKey ( ) throws NoSuchAlgorithmException {
        Random randomGenerator = SecureRandom.getInstance ( "SHA1PRNG" );
        return new BigInteger ( NUM_BITS , randomGenerator );
    }

    /**
     * Generates a public key using the private key.
     *
     * @param privateKey private key.
     *
     * @return public key.
     */
    public static BigInteger generatePublicKey ( BigInteger privateKey ) {
        return G.modPow ( privateKey , N );
    }

    /**
     * Generates a shared secret using the public key and the private key.
     *
     * @param publicKey public key.
     *
     * @param privateKey private key.
     *
     * @return  shared secret.
     */
    public static BigInteger computePrivateKey ( BigInteger publicKey , BigInteger privateKey ) {
        return publicKey.modPow ( privateKey , N );
    }

}