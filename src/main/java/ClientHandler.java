import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

/**
 * This class represents the client handler. It handles the communication with the client. It reads the file from the
 * server and sends it to the client.
 */
public class ClientHandler extends Thread {

    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final Socket client;
    private final boolean isConnected;

    /**
     * Creates a ClientHandler object by specifying the socket to communicate with the client. All the processing is
     * done in a separate thread.
     *
     * @param client the socket to communicate with the client
     *
     * @throws IOException when an I/O error occurs when creating the socket
     */
    public ClientHandler ( Socket client ) throws IOException {
        this.client = client;
        in = new ObjectInputStream ( client.getInputStream ( ) );
        out = new ObjectOutputStream ( client.getOutputStream ( ) );
        isConnected = true; // TODO: Check if this is necessary or if it should be controlled
    }

    @Override
    public void run ( ) {
        super.run ( );
        try {
            while ( isConnected ) {
                // Reads the message to extract the path of the file
                Message message = ( Message ) in.readObject ( );
                String request = new String ( message.getMessage ( ) );
                // Reads the file and sends it to the client
                byte[] content = FileHandler.readFile ( RequestUtils.getAbsoluteFilePath ( request ) );
                sendFile ( content );
            }
            // Close connection
            closeConnection ( );
        } catch ( IOException | ClassNotFoundException e ) {
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
    private void sendFile ( byte[] content ) throws IOException {
        Message response = new Message ( content );
        out.writeObject ( response );
        out.flush ( );
    }


    /**
     * Closes the connection by closing the socket and the streams.
     */
    private void closeConnection ( ) {
        try {
            client.close ( );
            out.close ( );
            in.close ( );
        } catch ( IOException e ) {
            throw new RuntimeException ( e );
        }
    }

}
