import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import static java.lang.Thread.sleep;

/**
 * This class represents a server that receives a message from the clients. The server is implemented as a thread. Each
 * time a client connects to the server, a new thread is created to handle the communication with the client.
 */
public class Server implements Runnable {


    public static final String FILE_PATH = "server/files";

    private static final String MAC_KEY = "Mas2142SS!±";
    private final ServerSocket server;
    private final boolean isConnected;
    private ObjectInputStream in;
    private ObjectOutputStream out;
    private final PrivateKey privateRSAKey;
    private final PublicKey publicRSAKey;

    /**
     * Constructs a Server object by specifying the port number. The server will be then created on the specified port.
     * The server will be accepting connections from all local addresses.
     *
     * @param port the port number
     * @throws IOException if an I/O error occurs when opening the socket
     */
    public Server(int port) throws Exception {
        server = new ServerSocket(port);
        isConnected = true; // TODO: Check if this is necessary or if it should be controlled
        KeyPair keyPair = Encryption.generateKeyPair();
        this.privateRSAKey = keyPair.getPrivate();
        this.publicRSAKey = keyPair.getPublic();
        File publicKeyFile = new File("pki/public_keys", "serverPUK.key");
        try (OutputStream outputStream = new FileOutputStream(publicKeyFile)) {
            outputStream.write(publicRSAKey.getEncoded());
        }
    }

    @Override
    public void run() {
        try {
            while (isConnected) {
                Socket client = server.accept();
                in = new ObjectInputStream(client.getInputStream());
                out = new ObjectOutputStream(client.getOutputStream());
                // Perform key distribution
                PublicKey senderPublicRSAKey = rsaKeyDistribution(in);
                // Process the request
                process(client, senderPublicRSAKey);
            }
            closeConnection();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Executes the key distribution protocol. The receiver will receive the public key of the sender and will send its
     * own public key.
     *
     * @param in the input stream
     * @return the public key of the sender
     * @throws Exception when the key distribution protocol fails
     */
    private PublicKey rsaKeyDistribution(ObjectInputStream in) throws Exception {
        // Extract the public key
        PublicKey clientPublicRSAKey = (PublicKey) in.readObject();
        // Send the public key
        sendPublicRSAKey();
        return clientPublicRSAKey;
    }

    /**
     * Processes the request from the client.
     *
     * @throws IOException if an I/O error occurs when reading stream header
     */
    private void process(Socket client, PublicKey clientPublicRSAKey) throws Exception {
        System.out.println("Processing Request...");
        // Agree on a shared secret
        BigInteger sharedSecret = agreeOnSharedSecret(clientPublicRSAKey);

        Message messageObj = (Message) in.readObject();
        // Extracts and decrypt the message
        byte[] decryptedMessage = Encryption.decryptMessage(messageObj.getMessage(), sharedSecret.toByteArray());
        // Computes the digest of the received message
        byte[] computedDigest = Integrity.generateDigest(decryptedMessage, MAC_KEY);
        // Verifies the integrity of the message
        if (!Integrity.verifyDigest(messageObj.getSignature(), computedDigest)) {
            throw new RuntimeException("The integrity of the message is not verified");
        }
        //prints the request received
        System.out.println (new String ( decryptedMessage ) );

        byte[] content = FileHandler.readFile ( RequestUtils.getAbsoluteFilePath (new String ( decryptedMessage ) ) );
        //Sending the file to the client, before sending check if the file is too big




        String mee = "hello this is";
        byte[] digest = Integrity.generateDigest ( mee.getBytes(),MAC_KEY);
        byte[] encryptedMessage = Encryption.encryptMessage ( mee.getBytes() , sharedSecret.toByteArray() );
        System.out.println("SECRET: " + Arrays.toString(sharedSecret.toByteArray()));

        Message response = new Message ( mee.getBytes(), digest);
        System.out.println("Encrypt MESSAGE: " + Arrays.toString(response.getMessage()));
        out.writeObject ( response );
        out.flush ( );

        /*creates a thread to answer the client
        ClientHandler clientHandler = new ClientHandler ( client ,sharedSecret);
        clientHandler.start ( );
*/
    }

    /**
     * Performs the Diffie-Hellman algorithm to agree on a shared private key.
     *
     * @param senderPublicRSAKey the public key of the sender
     * @return the shared secret key
     * @throws Exception when the key agreement protocol fails
     */
    private BigInteger agreeOnSharedSecret(PublicKey senderPublicRSAKey) throws Exception {
        // Generate a pair of keys
        BigInteger privateKey = DiffieHellman.generatePrivateKey();
        BigInteger publicKey = DiffieHellman.generatePublicKey(privateKey);
        // Extracts the public key from the request
        BigInteger clientPublicKey = new BigInteger(Encryption.decryptRSA((byte[]) in.readObject(), senderPublicRSAKey));
        // Send the public key to the client
        sendPublicDHKey(publicKey);
        // Generates the shared secret
        return DiffieHellman.computePrivateKey(clientPublicKey, privateKey);
    }

    /**
     * Sends the public key to the sender.
     *
     * @param publicKey the public key to be sent
     * @throws Exception when the public key cannot be sent
     */
    private void sendPublicDHKey(BigInteger publicKey) throws Exception {
        out.writeObject(Encryption.encryptRSA(publicKey.toByteArray(), this.privateRSAKey));
    }

    /**
     * Sends the public key of the receiver to the sender.
     *
     * @throws IOException when an I/O error occurs when sending the public key
     */
    private void sendPublicRSAKey() throws IOException {
        out.writeObject(publicRSAKey);
        out.flush();
    }

    /**
     * Closes the connection and the associated streams.
     */
    private void closeConnection() {
        try {
            server.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}