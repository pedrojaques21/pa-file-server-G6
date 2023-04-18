import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.util.Scanner;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * This class represents the client. The client sends the messages to the server by means of a socket. The use of Object
 * streams enables the sender to send any kind of object.
 */
public class Client {

    private String name;
    private static final String HOST = "0.0.0.0";
    private final Socket client;
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final boolean isConnected;
    private final String userDir;
    private final PublicKey publicRSAKey;
    private final PrivateKey privateRSAKey;
    private final PublicKey receiverPublicRSAKey;

    /**
     * Constructs a Client object by specifying the port to connect to. The socket must be created before the sender can
     * send a message.
     *
     * @param port the port to connect to
     *
     * @throws IOException when an I/O error occurs when creating the socket
     */
    public Client ( int port, String name ) throws Exception {
        this.name = name;
        client = new Socket ( HOST , port );
        out = new ObjectOutputStream ( client.getOutputStream ( ) );
        in = new ObjectInputStream ( client.getInputStream ( ) );
        isConnected = true; // TODO: Check if this is necessary or if it should be controlled
        KeyPair keyPair = Encryption.generateKeyPair ( );
        this.privateRSAKey = keyPair.getPrivate ( );
        this.publicRSAKey = keyPair.getPublic ( );
        // Performs the RSA key distribution
        receiverPublicRSAKey = rsaKeyDistribution ( );
        // Create a temporary directory for putting the request files
        userDir = Files.createTempDirectory ( "fileServer" ).toFile ( ).getAbsolutePath ( );
        System.out.println ( "Temporary directory path " + userDir );
    }


    /**
     * Performs the Diffie-Hellman algorithm to agree on a shared private key.
     *
     * @param receiverPublicRSAKey the public key of the receiver
     *
     * @return the shared private key
     *
     * @throws Exception when the Diffie-Hellman algorithm fails
     */
    private BigInteger agreeOnSharedSecret (PublicKey receiverPublicRSAKey ) throws Exception {
        // Generates a private key
        BigInteger privateDHKey = DiffieHellman.generatePrivateKey ( );
        BigInteger publicDHKey = DiffieHellman.generatePublicKey ( privateDHKey );
        // Sends the public key to the server encrypted
        sendPublicDHKey ( Encryption.encryptRSA ( publicDHKey.toByteArray ( ) , privateRSAKey ) );
        // Waits for the server to send his public key
        BigInteger serverPublicKey = new BigInteger ( Encryption.decryptRSA ( ( byte[] ) in.readObject ( ) , receiverPublicRSAKey ) );
        // Generates the shared secret
        return DiffieHellman.computePrivateKey ( serverPublicKey , privateDHKey );
    }

    /**
     * Sends the public key to the receiver.
     *
     * @param publicKey the public key to send
     *
     * @throws Exception when the public key cannot be sent
     */
    private void sendPublicDHKey ( byte[] publicKey ) throws Exception {
        out.writeObject ( publicKey );
    }

    /**
     * Executes the key distribution protocol. The sender sends its public key to the receiver and receives the public
     * key of the receiver.
     *
     * @return the public key of the sender
     *
     * @throws Exception when the key distribution protocol fails
     */
    private PublicKey rsaKeyDistribution ( ) throws Exception {
        // Sends the public key
        sendPublicRSAKey ( );
        // Receive the public key of the sender
        return ( PublicKey ) in.readObject ( );
    }

    /**
     * Sends the public key of the sender to the receiver.
     *
     * @throws IOException when an I/O error occurs when sending the public key
     */
    private void sendPublicRSAKey ( ) throws IOException {
        out.writeObject ( publicRSAKey );
        out.flush ( );
    }

    /**
     * Executes the client. It reads the file from the console and sends it to the server. It waits for the response and
     * writes the file to the temporary directory.
     */
    public void execute ( ) {
        Scanner usrInput = new Scanner ( System.in );
        try {
            while ( isConnected ) {
                // Reads the message to extract the path of the file
                System.out.println ( "Write the path of the file" );
                String request = usrInput.nextLine ( );
                // Request the file
                sendMessage ( request );
                // Waits for the response
                processResponse ( RequestUtils.getFileNameFromRequest ( request ) );
            }
            // Close connection
            closeConnection ( );
        } catch ( Exception e ) {
            throw new RuntimeException ( e );
        }
        // Close connection
        closeConnection ( );
    }

    /**
     * Reads the response from the server and writes the file to the temporary directory.
     *
     * @param fileName the name of the file to write
     */
    private void processResponse ( String fileName ) {
        try {
            Message response = ( Message ) in.readObject ( );
            System.out.println ( "File received" );
            FileHandler.writeFile ( userDir + "/" + fileName , response.getMessage ( ) );
        } catch ( IOException | ClassNotFoundException e ) {
            e.printStackTrace ( );
        }
    }

    /**
     * Sends the path of the file to the server using the OutputStream of the socket. The message is sent as an object
     * of the {@link Message} class.
     *
     * @param filePath the message to send
     *
     * @throws IOException when an I/O error occurs when sending the message
     */
    public void sendMessage ( String filePath ) throws Exception {
        // Agree on a shared secret
        BigInteger sharedSecret = agreeOnSharedSecret ( receiverPublicRSAKey );
        // Encrypts the message
        byte[] encryptedMessage = Encryption.encryptMessage ( filePath.getBytes ( ) , sharedSecret.toByteArray ( ) );
        // Generates the MAC
        byte[] digest = Integrity.generateDigest ( filePath.getBytes ( ) );
        // Creates the message object
        Message messageObj = new Message ( encryptedMessage , digest );
        // Sends the message
        out.writeObject ( messageObj );
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
