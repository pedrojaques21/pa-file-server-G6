import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;


/**
 * This class represents the client handler. It handles the communication with the client. It reads the file from the
 * server and sends it to the client.
 */
public class ClientHandler extends Thread {
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final Socket client;
    private final boolean isConnected;
    private PrivateKey privateRSAKey;
    private PublicKey publicRSAKey;
    private PublicKey senderPublicRSAKey;
    private BigInteger sharedSecret;
    private String clientName;
    private int numOfRequests;
    private String symmetricAlgorithm;
    private String hashingAlgorithm;
    private boolean isSupported;
    private boolean hashIsSupported;
    private byte[] macKey;

    /**
     * Creates a ClientHandler object by specifying the socket to communicate with the client. All the processing is
     * done in a separate thread.
     *
     * @param client represents the socket connection with the client
     *
     * @throws IOException when an I/O error occurs when creating the socket
     */
    public ClientHandler(Socket client) throws Exception {
        this.client = client;
        this.symmetricAlgorithm = "";
        this.hashingAlgorithm = "";
        in = new ObjectInputStream(client.getInputStream());
        out = new ObjectOutputStream(client.getOutputStream());

        // Get the encryption symmetric algorithm from the client
        this.symmetricAlgorithm = in.readUTF();
        isSupported = verifyAlgorithmServerSupport(this.symmetricAlgorithm);

        // Get encryption hashing algorithm from the client
        this.hashingAlgorithm = in.readUTF();
        hashIsSupported = verifyHashAlgorithmServerSupport(this.hashingAlgorithm);

        if(!isSupported | !hashIsSupported){
            sendErrorMessage();
        }else{
            sendSuccessMessage();
        }

        isConnected = true;
        KeyPair keyPair = Encryption.generateKeyPair();
        this.numOfRequests = 0;
        this.privateRSAKey = keyPair.getPrivate();
        this.publicRSAKey = keyPair.getPublic();
        File publicKeyFile = new File("pki/public_keys", "serverPUK.key");
        this.senderPublicRSAKey = rsaKeyDistribution(in);
        this.sharedSecret = agreeOnSharedSecret(senderPublicRSAKey);
        try (OutputStream outputStream = new FileOutputStream(publicKeyFile)) {
            outputStream.write(publicRSAKey.getEncoded());
        }
        this.macKey = receiveMacKey();
    }

    /**
     * Sends a success message to the client indicating that the selected algorithm is supported by the server.
     *
     * @throws IOException when an I/O error occurs when closing the socket
     */
    private void sendSuccessMessage() throws IOException {
        out.writeUTF("The selected Algorithm is supported by this server, enjoy!");
        System.out.println("The selected Algorithm is supported by this server, enjoy!");
        out.flush();
    }

    /**
     * Executes the key distribution protocol. The receiver will receive the public key of the sender and will send its
     * own public key.
     *
     * @param in the input stream
     *
     * @return the public key of the sender
     *
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
     * Reads the MacKey sent from the client soo that it can assign it to its own MacKey
     *
     * @return the key after decrypting it
     */

    public byte[] receiveMacKey() throws Exception{
        byte[] macKey = (byte[]) in.readObject();
        return Encryption.decryptMessage(macKey, sharedSecret.toByteArray(), symmetricAlgorithm);
    }

    /**
     * Performs the Diffie-Hellman algorithm to agree on a shared private key.
     *
     * @param senderPublicRSAKey the public key of the sender
     *
     * @return the shared secret key
     *
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
     *
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

    public BigInteger getSharedSecret() {
        return sharedSecret;
    }

    /**
     * Cycle responsible for receiving every request from the client
     * Also responsible for renewing the handshake
     */

    @Override
    public void run ( ) {
        super.run ( );
        try {
            while (isConnected) {
                int MAX_NUM_OF_REQUESTS = 5;
                if (this.numOfRequests < MAX_NUM_OF_REQUESTS) {
                    System.out.println("Processing Request...");
                    byte[] content = receiveMessage();
                    if(content.length == 0) {
                        System.out.println("Name received!");
                    }else{
                        sendFile(content);
                    }
                } else {
                    // Get the encryption symmetric algorithm from the client
                    this.symmetricAlgorithm = in.readUTF();
                    isSupported = verifyAlgorithmServerSupport(this.symmetricAlgorithm);

                    // Get encryption hashing algorithm from the client
                    this.hashingAlgorithm = in.readUTF();
                    hashIsSupported = verifyHashAlgorithmServerSupport(this.hashingAlgorithm);

                    if(!isSupported | !hashIsSupported){
                        sendErrorMessage();
                    }else{
                        sendSuccessMessage();
                    }

                    this.numOfRequests = 0;
                    MainServer.numOfRequestsMap = FileHandler.readHashMapFromFile(MainServer.NREQUESTSMAP_PATH);
                    MainServer.numOfRequestsMap.put(this.clientName, this.numOfRequests);
                    System.out.println("****************************************");
                    System.out.println("***      Renewing the Handshake      ***");
                    System.out.println("****************************************");

                    KeyPair keyPair = Encryption.generateKeyPair();
                    this.privateRSAKey = keyPair.getPrivate();
                    this.publicRSAKey = keyPair.getPublic();
                    this.senderPublicRSAKey = rsaKeyDistribution(in);
                    this.sharedSecret = agreeOnSharedSecret(senderPublicRSAKey);
                    this.macKey = receiveMacKey();
                    System.out.println("Processing Request...");
                    byte[] content = receiveMessage();
                    sendFile(content);
                }
            }
            // Close connection
            closeConnection();
        } catch (Exception e) {
            // Close connection
            closeConnection();
        }
    }

    /**
     * Method responsible for reading the message sent from the {@link Client}
     * Decrypts the message using the established algorithm
     * If the message starts with {@value = "NAME"} it means the client is introducing itself
     * soo it should not return a file but create a directory
     *
     * @return the path of the file or "nothing" to let the {@link ClientHandler} know to greet the client
     */
    private byte[] receiveMessage() throws Exception {
        Message messageObj = (Message) in.readObject();
        byte[] decryptedMessage = decryptMessage(messageObj);
        System.out.println(new String(decryptedMessage));
        // Reads the message to extract the path of the file
        String request = new String(decryptedMessage);
        if(!request.startsWith("NAME")) {
            // Reads the file and sends it to the client
            return FileHandler.readFile(RequestUtils.getAbsoluteFilePath(request));
        }else{
            String[] parts = request.split(":");
            String name = parts[1].trim();
            File rootDir = new File(".");
            File[] directories = rootDir.listFiles(File::isDirectory);
            assert directories != null;
            this.clientName = name;

            MainServer.numOfRequestsMap = FileHandler.readHashMapFromFile(MainServer.NREQUESTSMAP_PATH);
            //FileHandler.printHashMap(MainServer.numOfRequestsMap);
            if (!MainServer.numOfRequestsMap.containsKey(this.clientName)) {
                MainServer.numOfRequestsMap.put(this.clientName, this.numOfRequests);
            } else {
                this.numOfRequests = MainServer.numOfRequestsMap.get(this.clientName);
                System.out.println("*** Welcome again, " + this.clientName + "!");
                System.out.println("Number of Requests: " + numOfRequests);
            }
            return new byte[0];
        }
    }

    /**
     * Decrypts the message and verifies its integrity. If the integrity is verified,
     * the decrypted message is returned.
     *
     * @param messageObj is the message object that is being received from the client
     *
     * @return the decrypted message if its integrity is verified
     *
     * @throws Exception when the message cannot be decrypted or its integrity is not verified
     */
    private byte[] decryptMessage(Message messageObj) throws Exception {
        // Extracts and decrypt the message
        byte[] decryptedMessage = Encryption.decryptMessage(messageObj.getMessage(), sharedSecret.toByteArray(),
                symmetricAlgorithm);
        // Computes the digest of the received message
        byte[] computedDigest = Integrity.generateDigest(decryptedMessage, this.macKey,hashingAlgorithm);
        // Verifies the integrity of the message
        if (!Integrity.verifyDigest(messageObj.getSignature(), computedDigest)) {
            throw new RuntimeException("The integrity of the message is not verified");
        }
        return decryptedMessage;
    }

    /**
     * Sends the file to the client
     *
     * @param content the content of the file to send
     *
     * @throws IOException when an I/O error occurs when sending the file
     */
    private void sendFile(byte[] content) throws Exception {
        this.numOfRequests++;
        MainServer.numOfRequestsMap = FileHandler.readHashMapFromFile(MainServer.NREQUESTSMAP_PATH);
        MainServer.numOfRequestsMap.put(this.clientName, this.numOfRequests);
        FileHandler.saveHashMapToTextFile(MainServer.numOfRequestsMap, MainServer.NREQUESTSMAP_PATH);
        //Sending the file to the client, before sending check if the file is too big
        byte[] encryptedMessage = Encryption.encryptMessage(content, sharedSecret.toByteArray(), symmetricAlgorithm);
        byte[] digest = Integrity.generateDigest(content, this.macKey, hashingAlgorithm);
        Message response = new Message(encryptedMessage, digest);
        out.writeObject(response);
        out.flush();
    }

    /**
     * After checking if the received algorithm is not valid {@link ClientHandler()#verifyAlgorithmServerSupport()}
     * and alerts the client and closes the connection with it
     */
    private void sendErrorMessage() throws IOException {
        out.writeUTF("The selected Algorithm is not supported by this server!");
        System.out.println("The selected Algorithm is not supported by this server!");
        out.flush();
        closeConnection();
    }

    /**
     * Receive the symmetric algorithm selected by the client, and verify if the server support them
     *
     * @return boolean {@value = true if algorithm is available}
     */
    private boolean verifyAlgorithmServerSupport(String receivedAlgorithm) {
        String[] availableAlgorithms = {"AES", "DES", "DESede"};
        System.out.println("Received selected algorithm: " + receivedAlgorithm);
        boolean isAlgorithmAvailable = false;

        for (String availableAlgorithm : availableAlgorithms) {
            if (receivedAlgorithm.equals(availableAlgorithm)) {
                isAlgorithmAvailable = true;
                break;
            }
        }

        if (isAlgorithmAvailable) {
            System.out.println("Algorithm is available");
        } else {
            System.out.println("Algorithm is not available");
        }

        return isAlgorithmAvailable;
    }

    /**
     * Verifies if the algorithm received from the client is supported by the server.
     *
     * @param receivedAlgorithm the algorithm received from the client
     *
     * @return true if the algorithm is supported by the server, false otherwise
     */
    private boolean verifyHashAlgorithmServerSupport(String receivedAlgorithm) {
        String[] availableAlgorithms = {"HmacMD5", "HmacSHA256","HmacSHA512"};
        System.out.println("Received selected algorithm: " + receivedAlgorithm);
        boolean isAlgorithmAvailable = false;

        for (String availableAlgorithm : availableAlgorithms) {
            if (receivedAlgorithm.equals(availableAlgorithm)) {
                isAlgorithmAvailable = true;
                break;
            }
        }

        if (isAlgorithmAvailable) {
            System.out.println("Algorithm is available");
        } else {
            System.out.println("Algorithm is not available");
        }

        return isAlgorithmAvailable;
    }

    /**
     * Closes the connection by closing the socket and the streams.
     */
    private void closeConnection() {
        try {
            client.close();
            out.close();
            in.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
