import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Scanner;

/**
 * This class represents the client handler. It handles the communication with the client. It reads the file from the
 * server and sends it to the client.
 */
public class ClientHandler extends Thread {
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final Socket client;
    private boolean isConnected;

    private PrivateKey privateRSAKey;
    private PublicKey publicRSAKey;

    private PublicKey senderPublicRSAKey;

    private BigInteger sharedSecret;

    private String clientName;

    private final int MAX_NUM_OF_REQUESTS = 5;
    private int numOfRequests;

    private String symmetricAlgorithm;
    private String hashingAlgorithm;


    /**
     * Creates a ClientHandler object by specifying the socket to communicate with the client. All the processing is
     * done in a separate thread.
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
        System.out.println("Received selected algorithm: " + this.symmetricAlgorithm);
        //verifyAlgorithmServerSupport(this.symmetricAlgorithm);

        // Get encryption hashing algorithm from the client
        this.hashingAlgorithm = in.readUTF();
        System.out.println("Received selected algorithm: " + this.hashingAlgorithm.replace("Hmac", ""));
        //verifyAlgorithmServerSupport(this.hashingAlgorithm);

        isConnected = true; // TODO: Check if this is necessary or if it should be controlled
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

    @Override
    public void run ( ) {
        super.run ( );
        try {
            while (isConnected) {
                if (this.numOfRequests < MAX_NUM_OF_REQUESTS) {
                    System.out.println("Processing Request...");
                    byte[] content = receiveMessage();
                    if(content.length == 0) {
                        System.out.println("Name received!");
                    }else{
                        sendFile(content);
                    }
                } else {
                    this.numOfRequests = 0;
                    System.out.println("****************************************");
                    System.out.println("***      Renewing the Handshake      ***");
                    System.out.println("****************************************");

                    // Get the encryption symmetric algorithm from the client
                    this.symmetricAlgorithm = in.readUTF();
                    System.out.println("Received selected algorithm: " + this.symmetricAlgorithm);
                    //verifyAlgorithmServerSupport(this.symmetricAlgorithm);

                    // Get encryption hashing algorithm from the client
                    this.hashingAlgorithm = in.readUTF();
                    System.out.println("Received selected algorithm: " + this.hashingAlgorithm.replace("Hmac", ""));
                    //verifyAlgorithmServerSupport(this.hashingAlgorithm);

                    KeyPair keyPair = Encryption.generateKeyPair();
                    this.privateRSAKey = keyPair.getPrivate();
                    this.publicRSAKey = keyPair.getPublic();
                    this.senderPublicRSAKey = rsaKeyDistribution(in);
                    this.sharedSecret = agreeOnSharedSecret(senderPublicRSAKey);
                    System.out.println("SHARED: " + Arrays.toString(sharedSecret.toByteArray()));
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
            for (File directory : directories) {
                if (directory.getName().equals(this.clientName)) {
                    String filePath = directory + File.separator + "client.config";
                    int num = 0;
                    File file = new File(filePath);
                    if (file.exists() && file.canRead()) {
                        Scanner scanner = new Scanner(file);
                        if(scanner.hasNextLine()) {
                            num = Integer.parseInt(scanner.nextLine());
                            this.numOfRequests = num;
                            scanner.close();
                        }else{
                            this.numOfRequests = 0;
                        }
                    }else{
                        System.out.println("O arquivo não existe ou não pode ser lido");
                    }
                }
            }

            return new byte[0];
        }
    }

    private byte[] decryptMessage(Message messageObj) throws Exception {
        // Extracts and decrypt the message
        byte[] decryptedMessage = Encryption.decryptMessage(messageObj.getMessage(), sharedSecret.toByteArray(),
                symmetricAlgorithm);
        // Computes the digest of the received message
        byte[] computedDigest = Integrity.generateDigest(decryptedMessage, sharedSecret.toByteArray(),hashingAlgorithm);
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
     * @throws IOException when an I/O error occurs when sending the file
     */
    private void sendFile(byte[] content) throws Exception {
        System.out.println("Hello " + this.clientName);
        this.numOfRequests++;
        //Sending the file to the client, before sending check if the file is too big
        byte[] encryptedMessage = Encryption.encryptMessage(content, sharedSecret.toByteArray(), symmetricAlgorithm);
        byte[] digest = Integrity.generateDigest(content, sharedSecret.toByteArray(), hashingAlgorithm);
        Message response = new Message(encryptedMessage, digest);
        out.writeObject(response);
        out.flush();
    }

    /**
     * Receive the algorithms selected by the client, and verify if the server support them
     */
    private void verifyAlgorithmServerSupport(String algorithm) throws IOException {
        String algorithmsNameGrouped = "AESDES3DESede";
        algorithm = in.readUTF();
        System.out.println("Received selected algorithm: " + algorithm);
        out.writeBoolean((true ? true : false));
//
//        String algorithmsNameGrouped = "AESDES3DESede";
//        try {
//            algorithm = in.readUTF();
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        } finally{
//            System.out.println("Received selected algorithm: " + algorithm);
//            Boolean algorithmExists = (algorithmsNameGrouped.contains(algorithm) ? true : false);
//            try {
//                out.writeBoolean((algorithmExists ? true : false));
//            } catch (IOException e) {
//                throw new RuntimeException(e);
//            }
//        }



    }




    //algorithmValidation(this.symmetricAlgorithm);

    //algorithmValidation(this.symmetricAlgorithm);

    /**
     * Validation of algorithms supported by the server
     */
//    public void algorithmValidation(String algorithm) {
//        if (!algorithm){
//            out.writeUTF("NOK! Algorithm not supported by the server.\nSelect a valid one.");
//        } else {
//            out.writeUTF("OK! Algorithm supported.");
//        }
//
//    }
//    "Received selected algorithm: " + this.symmetricAlgorithm + "!"


    /**
     * Closes the connection by closing the socket and the streams.
     */
    private void closeConnection() {
        try {
            isConnected = false;
            this.out.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
