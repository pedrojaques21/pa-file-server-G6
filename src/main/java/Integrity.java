import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

    /**
     * This class implements the generation and verification of the message authentication code (MAC).
     */
    public class Integrity {

        /**
         * Generates the message authentication code (MAC) of the message.
         *
         * @return the message authentication code
         *
         * @throws Exception when the MAC generation fails
         */
        public static byte[] generateDigest ( byte[] message , byte[] macKey, String MAC_ALGORITHM  ) throws Exception {
            SecretKeySpec secretKeySpec = new SecretKeySpec ( macKey , MAC_ALGORITHM  );
            Mac mac = Mac.getInstance ( MAC_ALGORITHM  );
            mac.init ( secretKeySpec );
            return mac.doFinal ( message );
        }

        /**
         * Verifies the message digest of the given message.
         *
         * @param digest         the message digest to be verified
         * @param computedDigest the computed message digest
         *
         * @return true if the message digest is valid, false otherwise
         */
        public static boolean verifyDigest ( byte[] digest , byte[] computedDigest ) {
            return Arrays.equals ( digest , computedDigest );
        }

    }