import java.io.Serializable;

/**
 * This class represents a message object that is sent between the client and the server.
 */
public class Message implements Serializable {

    private final byte[] message;
    private final byte[] signature;

    /**
     * Constructs a Message object by specifying the message bytes that will be sent between the client and the server.
     *
     * @param message   the message that is sent to the server
     * @param signature the signature of the sender
     */
    public Message ( byte[] message , byte[] signature ) {
        this.message = message;
        this.signature = signature;
    }

    /**
     * Gets the message string.
     *
     * @return the message string
     */
    public byte[] getMessage ( ) {
        return message;
    }

    /**
     * Gets the signature of the message.
     *
     * @return the digest of the message
     */
    public byte[] getSignature ( ) {
        return signature;
    }
}