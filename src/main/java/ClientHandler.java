import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PrivateKey;
import java.util.Arrays;

/**
 * This class represents the client handler. It handles the communication with the client. It reads the file from the
 * server and sends it to the client.
 */
public class ClientHandler extends Thread {

    private ObjectInputStream in;
    private static final String MAC_KEY = "Mas2142SS!±";
    private ObjectOutputStream out;
    private final Socket client;
    private final boolean isConnected;

    private final BigInteger sharedSecret;

    private byte[] messageToSend;


    /**
     * Creates a ClientHandler object by specifying the socket to communicate with the client. All the processing is
     * done in a separate thread.
     *
     * @param client the socket to communicate with the client
     *
     * @throws IOException when an I/O error occurs when creating the socket
     */
    public ClientHandler (Socket client, byte[] message,  BigInteger sharedSecret ) throws IOException {
        this.sharedSecret = sharedSecret;
        messageToSend = message;
        this.client = client;
        isConnected = true; // TODO: Check if this is necessary or if it should be controlled
        out = new ObjectOutputStream ( client.getOutputStream ( ) );
    }

    @Override
    public void run ( ) {
        super.run ( );
        try {
            while ( isConnected ) {
                // Reads the message to extract the path of the file
                String request = new String ( messageToSend );
                // Reads the file and sends it to the client
                byte[] content = FileHandler.readFile ( RequestUtils.getAbsoluteFilePath ( request ) );
                sendFile ( content );
            }
            // Close connection
            closeConnection ( );
        } catch ( Exception e ) {
            // Close connection
            closeConnection ( );
        }
    }

    /**
     * Sends the file to the client
     *
     * @param content the content of the file to send
     *
     * @throws IOException when an I/O error occurs when sending the file
     */
    private void sendFile ( byte[] content ) throws Exception {
        //Sending the file to the client, before sending check if the file is too big
        byte[] encryptedMessage = Encryption.encryptMessage ( content , sharedSecret.toByteArray() );
        byte[] digest = Integrity.generateDigest ( content,MAC_KEY);
        Message response = new Message ( encryptedMessage, digest);
        out.writeUnshared ( response );
        out.flush ( );
        closeConnection();
    }


    /**
     * Closes the connection by closing the socket and the streams.
     */
    private void closeConnection ( ) {
        try {
            client.close ( );
            out.close ( );
        } catch ( IOException e ) {
            throw new RuntimeException ( e );
        }
    }

}
