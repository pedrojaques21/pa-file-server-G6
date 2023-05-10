import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

/**
 * This class represents the client. The client sends the messages to the server by means of a socket. The use of Object
 * streams enables the sender to send any kind of object.
 */
public class Client {

    private final String name;
    private static final String HOST = "0.0.0.0";
    private final Socket client;
    private int numOfRequests;
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private boolean isConnected;
    private PublicKey publicRSAKey;
    private PrivateKey privateRSAKey;
    private PublicKey serverPublicRSAKey;
    private BigInteger sharedSecret;
    private String symmetricAlgorithm;
    private String hashingAlgorithm;
    public static Scanner input = new Scanner(System.in);
    private final boolean clientExists;
    private final File userDirectory;

    private byte[] macKey;

    /**
     * Constructs a Client object by specifying the port to connect to. The socket must be created before the sender can
     * send a message.
     *
     * @param port the port to connect to
     * @param name the name of the client
     * @param wayToChooseSymmetric the way to choose the symmetric algorithm
     * @param wayToChooseHashing the way to choose the hashing algorithm
     *
     * @throws IOException when an I/O error occurs when creating the socket
     */
    public Client(int port, String name, String wayToChooseSymmetric, String wayToChooseHashing) throws Exception {

        this.name = name;
        this.numOfRequests = 0;
        this.symmetricAlgorithm = "";
        this.hashingAlgorithm = "";

        client = new Socket(HOST, port);
        this.out = new ObjectOutputStream(client.getOutputStream());
        this.in = new ObjectInputStream(client.getInputStream());
        isConnected = true;
        // Create a "private" directory for the client
        userDirectory = new File(this.name);
        if (!userDirectory.exists()) {
            clientExists = false;
            userDirectory.mkdirs();
        } else {
            if (!MainServer.numOfRequestsMap.isEmpty()) {
                MainServer.numOfRequestsMap = FileHandler.readHashMapFromFile(MainServer.NREQUESTSMAP_PATH);
                this.numOfRequests = MainServer.numOfRequestsMap.get(this.name);
                clientExists = true;
            } else {
                clientExists = false;
            }
        }

        handshake(wayToChooseSymmetric, wayToChooseHashing);

        this.macKey = generateMacKey();
        sendMacKey();
        File filesDirectory = new File(userDirectory.getAbsolutePath() + "/files");
        if (!filesDirectory.exists()) {
            filesDirectory.mkdirs();
        }
    }

    public String getName() {
        return name;
    }

    public Socket getClient() {
        return client;
    }

    public PublicKey getPublicRSAKey() {
        return publicRSAKey;
    }

    public PrivateKey getPrivateRSAKey() {
        return privateRSAKey;
    }

    public PublicKey getServerPublicRSAKey() {
        return serverPublicRSAKey;
    }

    public BigInteger getSharedSecret() {
        return sharedSecret;
    }

    public ObjectInputStream getIn() {
        return in;
    }

    public byte[] getMacKey() {
        return macKey;
    }

    public void setMacKey(byte[] macKey) {
        this.macKey = macKey;
    }

    /**
     * Realizes the Diffie-Hellman key distribution protocol to agree on a shared private key.
     *
     * @param wayToChooseHashing the way to choose the hashing algorithm
     * @param wayToChooseSymmetric the way to choose the symmetric algorithm
     *
     * @throws Exception when an I/O error occurs when closing the socket
     */
    private void handshake(String wayToChooseSymmetric, String wayToChooseHashing) throws Exception {

        if (wayToChooseSymmetric.equals("User")) {
            this.symmetricAlgorithm = menuSymmetricAlgorithm();
            out.writeUTF(this.symmetricAlgorithm);
            out.flush();
            System.out.println("Sent to server the selected algorithm: " + this.symmetricAlgorithm);

            this.hashingAlgorithm = menuHashingAlgorithm();
            out.writeUTF(this.hashingAlgorithm);
            out.flush();
            System.out.println("Sent to server the selected algorithm: " + this.hashingAlgorithm);
        } else {
            this.symmetricAlgorithm = wayToChooseSymmetric;
            out.writeUTF(this.symmetricAlgorithm);
            out.flush();
            this.hashingAlgorithm = wayToChooseHashing;
            out.writeUTF(this.hashingAlgorithm);
            out.flush();
        }
        String response = in.readUTF();
        if (response.equals("The selected Algorithm is not supported by this server!")) {
            System.out.println("**********************************************************************");
            System.out.println("*** Error: The selected Algorithm is not supported by this server! ***");
            System.out.println("***              You are now going to be disconnected!             ***");
            System.out.println("**********************************************************************");
            closeConnection(1);
        } else {
            System.out.println("*** " + response + " ***");
        }

        //generate keys
        KeyPair keyPair = Encryption.generateKeyPair();

        //set client private key
        this.privateRSAKey = keyPair.getPrivate();

        //set client public key
        this.publicRSAKey = keyPair.getPublic();

        File privateDirectory = new File(userDirectory.getAbsolutePath() + "/private");
        if (!privateDirectory.exists()) {
            privateDirectory.mkdirs();
        }

        // Save the private key to a file in the "private" directory
        File privateKeyFile = new File(privateDirectory, "private.key");
        try (OutputStream outputStream = new FileOutputStream(privateKeyFile)) {
            outputStream.write(privateRSAKey.getEncoded());
        }

        // Save the public key to a file in the "public_keys" directory
        File publicKeyFile = new File("pki/public_keys", this.name + "PUK.key");
        try (OutputStream outputStream = new FileOutputStream(publicKeyFile)) {
            outputStream.write(publicRSAKey.getEncoded());
        }

        // Performs the RSA key distribution
        serverPublicRSAKey = rsaKeyDistribution();

        this.sharedSecret = agreeOnSharedSecret(serverPublicRSAKey);
    }

    /**
     * This function is responsible to generate for each client a unique MacKey
     * Inside the function it receives the chosen hashing algorithm and encodes de key
     *
     * @return the encoded key
     *
     * @throws NoSuchAlgorithmException if the hashing algorithm does not exist
     */
    private byte[] generateMacKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(this.hashingAlgorithm);
        SecretKey secretKey = keyGen.generateKey();
        return secretKey.getEncoded();
    }

    /**
     * This method is responsible for sending the generated key to the {@link ClientHandler}
     * The key is sent in an encrypted way using the chosen symmetric algorithm and the shared secret
     */
    private void sendMacKey() throws Exception {
        byte[] encryptedMessage = Encryption.encryptMessage(this.macKey, sharedSecret.toByteArray(),this.symmetricAlgorithm);
        out.writeObject(encryptedMessage);
        out.flush();
    }



    /**
     * Performs the Diffie-Hellman algorithm to agree on a shared private key.
     *
     * @param serverPublicRSAKey the public key of the receiver
     *
     * @return the shared private key
     *
     * @throws Exception when the Diffie-Hellman algorithm fails
     */
    private BigInteger agreeOnSharedSecret(PublicKey serverPublicRSAKey) throws Exception {
        // Generates a private key
        BigInteger privateDHKey = DiffieHellman.generatePrivateKey();
        //Generates a public key based on the private key
        BigInteger publicDHKey = DiffieHellman.generatePublicKey(privateDHKey);
        // Sends the public key to the server encrypted
        sendPublicDHKey(Encryption.encryptRSA(publicDHKey.toByteArray(), privateRSAKey));
        // Waits for the server to send his public key
        BigInteger serverPublicKey = new BigInteger(Encryption.decryptRSA((byte[]) in.readObject(), serverPublicRSAKey));
        // Generates the shared secret
        return DiffieHellman.computePrivateKey(serverPublicKey, privateDHKey);
    }

    /**
     * Executes the key distribution protocol. The sender sends its public key to the receiver and receives the public
     * key of the receiver.
     *
     * @return the public key of the sender
     *
     * @throws Exception when the key distribution protocol fails
     */
    private PublicKey rsaKeyDistribution() throws Exception {
        // Sends the public key
        sendPublicRSAKey();
        // Receive the public key of the sender
        return (PublicKey) in.readObject();
    }

    /**
     * Sends the public key to the receiver.
     *
     * @param publicKey the public key to send
     *
     * @throws Exception when the public key cannot be sent
     */
    private void sendPublicDHKey(byte[] publicKey) throws Exception {
        out.writeObject(publicKey);
    }

    /**
     * Sends the public key of the sender to the receiver.
     *
     * @throws IOException when an I/O error occurs when sending the public key
     */
    private void sendPublicRSAKey() throws IOException {
        out.writeObject(publicRSAKey);
        out.flush();
    }

    /**
     * Executes the client. It reads the file from the console and sends it to the server. It waits for the response and
     * writes the file to the {@link Client} directory.
     * Also sends the clients name to the server
     * Enters a cycle does only ends when the client disconnect
     * After 5 request renews the handshake with the server
     */
    public void execute() {
        Scanner usrInput = new Scanner(System.in);
        try {
            String clientName = "NAME" + " : " + this.name;
            greeting(clientName);
            int MAX_NUM_OF_REQUESTS = 5;
            if (clientExists) {
                System.out.println("*** Welcome again, " + this.name + "! ***");
                System.out.println("Number of Requests Remaining: " + (MAX_NUM_OF_REQUESTS - this.numOfRequests));
            } else {
                System.out.println("*** Welcome, " + this.name + "! ***\n You are now able to enjoy file storage.");
            }
            while (isConnected) {
                if (this.numOfRequests < MAX_NUM_OF_REQUESTS) {
                    // Reads the message to extract the path of the file
                    System.out.println("**********************************************************");
                    System.out.println("***            Write the path of the file              ***");
                    System.out.println("*** With the following format: GET : nameOfTheFile.txt ***");
                    System.out.println("**********************************************************\n");
                    String request = usrInput.nextLine();
                    // Request the file
                    sendMessage(request);
                    // Waits for the response
                    processResponse(RequestUtils.getFileNameFromRequest(request), in);

                } else {

                    System.out.println("****************************************");
                    System.out.println("***      Renewing the Handshake      ***");
                    System.out.println("****************************************\n");
                    renewHandshake("User", "User");
                    this.macKey = generateMacKey();
                    sendMacKey();

                    this.numOfRequests = 0;
                    System.out.println("**********************************************************");
                    System.out.println("***            Write the path of the file              ***");
                    System.out.println("*** With the following format: GET : nameOfTheFile.txt ***");
                    System.out.println("**********************************************************\n");
                    String request = usrInput.nextLine();
                    // Request the file
                    sendMessage(request);
                    //waits for the server response
                    processResponse(RequestUtils.getFileNameFromRequest(request), in);
                }
            }
            // Close connection
            closeConnection(2);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        // Close connection
        closeConnection(2);
    }

    /**
     * Renews the Handshake after 5 requests to the server
     * Asking the user which algorithms he wants to use and renews all the keys used
     */

    public void renewHandshake(String wayToChooseSymmetric, String wayToChooseHashing) throws Exception {

        if (wayToChooseSymmetric.equals("User")) {
            this.symmetricAlgorithm = menuSymmetricAlgorithm();
            out.writeUTF(this.symmetricAlgorithm);
            out.flush();
            System.out.println("Sent to server the selected algorithm: " + this.symmetricAlgorithm);

            this.hashingAlgorithm = menuHashingAlgorithm();
            out.writeUTF(this.hashingAlgorithm);
            out.flush();
            System.out.println("Sent to server the selected algorithm: " + this.hashingAlgorithm);
        } else {
            this.symmetricAlgorithm = wayToChooseSymmetric;
            out.writeUTF(this.symmetricAlgorithm);
            out.flush();
            this.hashingAlgorithm = wayToChooseHashing;
            out.writeUTF(this.hashingAlgorithm);
            out.flush();
        }

        String response = in.readUTF();
        if (response.equals("The selected Algorithm is not supported by this server!")) {
            System.out.println("**********************************************************************");
            System.out.println("*** Error: The selected Algorithm is not supported by this server! ***");
            System.out.println("***              You are now going to be disconnected!             ***");
            System.out.println("**********************************************************************");
            closeConnection(1);
        } else {
            System.out.println("*** " + response + " ***");
        }

        //generate keys
        KeyPair keyPair = Encryption.generateKeyPair();
        //set client private key
        this.privateRSAKey = keyPair.getPrivate();
        //set client public key
        this.publicRSAKey = keyPair.getPublic();
        // Performs the RSA key distribution
        serverPublicRSAKey = rsaKeyDistribution();
        this.sharedSecret = agreeOnSharedSecret(serverPublicRSAKey);
        System.out.println("****************************************");
        System.out.println("***        Handshake Renewed!        ***");
        System.out.println("****************************************\n");
    }

    /**
     * Reads the response from the server, decrypts it, and writes the file to the Client directory.
     *
     * @param fileName the name of the file to write
     * @param in the input stream from which to read the response
     *
     * @return the decrypted message for testing purposes
     *
     * * @throws Exception if an error occurs while reading the response or writing the file
     */
    public byte[] processResponse(String fileName, ObjectInputStream in) throws Exception {
        try {
            System.out.println("File received...");
            // Reads the encrypted message from the server
            Message response = (Message) in.readObject();
            // Decrypts the message using the shared secret key
            byte[] decryptedMessage = Encryption.decryptMessage(response.getMessage(), sharedSecret.toByteArray(),
                    this.symmetricAlgorithm);
            // Verifies the integrity of the decrypted message using the signature
            byte[] computedMac = Integrity.generateDigest(decryptedMessage, this.macKey,
                    this.hashingAlgorithm);
            if (!Integrity.verifyDigest(response.getSignature(), computedMac)) {
                throw new RuntimeException("The message has been tampered with!");
            }
            //Writes the decrypted message to the console
            System.out.println("Decrypted Message: " + new String(decryptedMessage) + "\n");
            // Check if the decrypted message starts with "ERROR"
            if (new String(decryptedMessage).startsWith("ERROR")) {
                // Print an error message
                System.out.println("*****************************************************************************************");
                System.out.println("***                 Error: the file you requested does not exist!                     ***");
                System.out.println("***      Your number of allowed requests before handshake renew decreased by one      ***");
                System.out.println("***                               Choose another one!                                 ***");
                System.out.println("*****************************************************************************************");
            } else {
                // Writes the decrypted message to the file
                FileHandler.writeFile(this.name + "/files/" + fileName, new String(decryptedMessage).getBytes());
            }
            return decryptedMessage;//Returns for testing purposes
        } catch (StreamCorruptedException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }


    /**
     * Responsible for letting the server know the clients name
     *
     * @param name - name of the client
     *
     * @throws Exception if an error occurs while sending the message
     */
    public void greeting(String name) throws Exception {
        // Encrypts the message
        byte[] encryptedMessage = Encryption.encryptMessage(name.getBytes(), sharedSecret.toByteArray(),
                this.symmetricAlgorithm);
        // Generates the MAC
        byte[] digest = Integrity.generateDigest(name.getBytes(), this.macKey,
                this.hashingAlgorithm);
        // Creates the message object
        Message messageObj = new Message(encryptedMessage, digest);
        // Sends the message
        out.writeUnshared(messageObj);
        out.flush();
    }

    /**
     * Sends the path of the file to the server using the OutputStream of the socket. The message is sent as an object
     * of the {@link Message} class.
     *
     * @param filePath the message to send
     *
     * @throws IOException when an I/O error occurs when sending the message
     */
    public Message sendMessage(String filePath) throws Exception {
        this.numOfRequests++;
        // Encrypts the message
        byte[] encryptedMessage = Encryption.encryptMessage(filePath.getBytes(), sharedSecret.toByteArray(),
                this.symmetricAlgorithm);
        // Generates the MAC
        byte[] digest = Integrity.generateDigest(filePath.getBytes(), this.macKey,
                this.hashingAlgorithm);
        // Creates the message object
        Message messageObj = new Message(encryptedMessage, digest);
        // Sends the message
        out.writeUnshared(messageObj);
        out.flush();
        return messageObj;
    }


    /**
     * Selecting alternative options of symmetric algorithm
     *
     * @return the selected algorithm for symmetric encryption
     */
    public String menuSymmetricAlgorithm() {
        int option = 0;
        do {
            System.out.println("*************************************************************");
            System.out.println("***           Encryption Symmetric Algorithm              ***");
            System.out.println("*** (1)-AES256; (2)-DES; (3)-3DES; (4)-RC4(Not supported) ***");
            System.out.println("*************************************************************");
            try {
                option = input.nextInt();
                input.nextLine(); //
            } catch (Exception e) {
                System.out.println("Invalid input.");
                input.nextLine();
                continue;
            }

            switch (option) {
                case 1 -> {
                    this.symmetricAlgorithm = "AES";
                    //symmetricKey = 256;
                    System.out.println("Implementing AES, key size 256 ...");
                }
                case 2 -> {
                    this.symmetricAlgorithm = "DES";
                    //symmetricKey = 64;
                    System.out.println("Implementing DES, key size 56(64) ...");
                }
                case 3 -> {
                    this.symmetricAlgorithm = "DESede";
                    //symmetricKey = 192;
                    System.out.println("Implementing 3DES, key size 168 ...");
                }
                case 4 -> {
                    this.symmetricAlgorithm = "RC4";
                    System.out.println("Trying to implement RC4 ...");
                }
            }
        } while (option < 1 && option > 4);

        return this.symmetricAlgorithm;
    }

    /**
     * Selecting alternative options of hashing algorithm
     *
     * @return The hashing algorithm selected
     */
    public String menuHashingAlgorithm() {
        int option = 0;
        do {
            System.out.println("*****************************************************************");
            System.out.println("***                    Hashing Algorithm                      ***");
            System.out.println("*** (1)-MD5; (2)-SHA256; (3)-SHA512; (4)Blake2(Not Supported) ***");
            System.out.println("*****************************************************************");
            try {
                option = input.nextInt();
                input.nextLine(); //
            } catch (Exception e) {
                System.out.println("Invalid input.");
                input.nextLine();
                continue;
            }

            switch (option) {
                case 1 -> {
                    this.hashingAlgorithm = "HmacMD5";
                    System.out.println("Implementing MD5, key size 128...");
                }
                case 2 -> {
                    this.hashingAlgorithm = "HmacSHA256";
                    System.out.println("Implementing SHA-3, key size 256...");
                }
                case 3 -> {
                    this.hashingAlgorithm = "HmacSHA512";
                    System.out.println("Implementing SHA-3, key size 512...");
                }
                case 4 -> {
                    this.hashingAlgorithm = "Blake2";
                    System.out.println("Trying to implement Blake2...");
                }
            }
        } while (option < 1 && option > 4);
        return this.hashingAlgorithm;
    }

    public String getSymmetricAlgorithm() {
        return symmetricAlgorithm;
    }

    public String getHashingAlgorithm() {
        return hashingAlgorithm;
    }

    /**
     * Closes the connection by closing the socket, the streams and sets isConnected to false
     * soo that the cycles ends.
     *
     * @param type {@value = 1} mainly used for testing purposes soo that its possible to
     * catch the error and prove that the user selected a wrong choice.
     */
    private void closeConnection(int type) {
        try {
            this.isConnected = false;
            client.close();
            out.close();
            in.close();
            if (type == 1) {
                throw new IllegalArgumentException("Invalid choice");
            } else {
                System.exit(0);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
