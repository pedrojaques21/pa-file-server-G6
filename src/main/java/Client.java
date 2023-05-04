import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Scanner;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * This class represents the client. The client sends the messages to the server by means of a socket. The use of Object
 * streams enables the sender to send any kind of object.
 */
public class Client {

    private final String name;
    private static final String HOST = "0.0.0.0";
    private final Socket client;
    private int numOfRequests;
    private final int MAX_NUM_OF_REQUESTS = 5;
    private File newConfigFile;
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final boolean isConnected;
    private final String userDir;
    private PublicKey publicRSAKey;
    private PrivateKey privateRSAKey;
    private PublicKey serverPublicRSAKey;
    private BigInteger sharedSecret;

    public static String symmetricAlgorithm;
    public static int symmetricKey;
    public static String hashingAlgorithm;
    public  static Scanner input = new Scanner(System.in);


    private boolean clientExists;

    private File userDirectory;

    /**
     * Constructs a Client object by specifying the port to connect to. The socket must be created before the sender can
     * send a message.
     *
     * @param port the port to connect to
     * @throws IOException when an I/O error occurs when creating the socket
     */
    public Client(int port, String name) throws Exception {

        this.name = name;
        this.numOfRequests = 0;

        client = new Socket(HOST, port);
        out = new ObjectOutputStream(client.getOutputStream());
        in = new ObjectInputStream(client.getInputStream());
        isConnected = true; // TODO: Check if this is necessary or if it should be controlled
        // Create a "private" directory for the client
        userDirectory = new File(this.name);
        if (!userDirectory.exists()) {
            clientExists = false;
            userDirectory.mkdirs();
        } else {
            clientExists = true;
        }

        handshake();
        File filesDirectory = new File(userDirectory.getAbsolutePath() + "/files");
        if (!filesDirectory.exists()) {
            filesDirectory.mkdirs();
        }

        // Create a temporary directory for putting the request files
        userDir = Files.createTempDirectory("fileServer").toFile().getAbsolutePath();
        System.out.println("Temporary directory path " + userDir);
    }



    private void handshake() throws Exception {

        // Selecting symmetric and hashing algorithms
        symmetricAlgorithm = menuSymmetricAlgorithm();
        hashingAlgorithm = menuHashingAlgorithm();

        // send selected protocols to the server
        out.writeUTF(symmetricAlgorithm);
        out.writeInt(symmetricKey);
        System.out.println("sent to server the selected algorithm: " + symmetricAlgorithm);


        System.out.println("");

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
     * Performs the Diffie-Hellman algorithm to agree on a shared private key.
     *
     * @param serverPublicRSAKey the public key of the receiver
     * @return the shared private key
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
     * writes the file to the temporary directory.
     */
    public void execute() throws Exception {
        Scanner usrInput = new Scanner(System.in);

        userRegistration(name); // 0 if new or a value from MainServer.numOfRequestsMap
        try {
            String clientName = "NAME" + " : " + this.name;
            greeting(clientName);
            if (clientExists) {
                System.out.println("Vamos consultar");
                String filePath = userDirectory.getAbsolutePath() + File.separator + "client.config";
                newConfigFile = new File(filePath);
                int num = 0;
                Scanner scanner = new Scanner(newConfigFile);
                num = Integer.parseInt(scanner.nextLine());
                System.out.println("Valor do num: " + num);
                this.numOfRequests = num;
                scanner.close();
            } else {
                String configFile = "client.config";
                newConfigFile = new File(userDirectory.getAbsolutePath(), configFile);
                if (!newConfigFile.exists()) {
                    newConfigFile.createNewFile();
                    System.out.println("O arquivo " + newConfigFile + " foi criado com sucesso.");
                    BufferedWriter writer = new BufferedWriter(new FileWriter(newConfigFile));
                    writer.write(Integer.toString(this.numOfRequests));
                    writer.close();
                } else {
                    System.out.println("O arquivo " + newConfigFile + " já existe.");
                }
            }
            while (isConnected) {
                if (this.numOfRequests < MAX_NUM_OF_REQUESTS) {
                    // Reads the message to extract the path of the file
                    System.out.println("TEST: " + Arrays.toString(sharedSecret.toByteArray()));
                    System.out.println("****************************************");
                    System.out.println("***    Write the path of the file    ***");
                    System.out.println("****************************************\n");
                    String request = usrInput.nextLine();
                    // Request the file
                    sendMessage(request);
                    // update value of the file
                    BufferedWriter writer = new BufferedWriter(new FileWriter(newConfigFile));
                    writer.write(Integer.toString(this.numOfRequests));
                    writer.close();
                    // Waits for the response
                    processResponse(RequestUtils.getFileNameFromRequest(request), in);

                } else {

                    System.out.println("****************************************");
                    System.out.println("***      Renewing the Handshake      ***");
                    System.out.println("****************************************\n");
                    this.numOfRequests = 0;
                    renewHandshake();
                    System.out.println("****************************************");
                    System.out.println("***    Write the path of the file    ***");
                    System.out.println("****************************************");
                    String request = usrInput.nextLine();
                    // Request the file
                    sendMessage(request);
                    // update value of the file
                    BufferedWriter writer = new BufferedWriter(new FileWriter(newConfigFile));
                    writer.write(Integer.toString(this.numOfRequests));
                    writer.close();
                    //waits for the server response
                    processResponse(RequestUtils.getFileNameFromRequest(request), in);
                }
            }
            // Close connection
            closeConnection();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        // Close connection
        closeConnection();
    }

    /**
     * Renews the Handshake after 5 requests to the server
     */
    private void renewHandshake() throws Exception {

        // Selecting symmetric and hashing algorithms
        symmetricAlgorithm = menuSymmetricAlgorithm();
        hashingAlgorithm = menuHashingAlgorithm();

        // send selected protocols to the server
        out.writeUTF(symmetricAlgorithm);
        out.writeInt(symmetricKey);
        System.out.println("sent to server the selected algorithm: " + symmetricAlgorithm);

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
     * Reads the response from the server, decrypts it, and writes the file to the temporary directory.
     *
     * @param fileName the name of the file to write
     */
    private void processResponse(String fileName, ObjectInputStream in) throws Exception {
        try {
            System.out.println("File received...");
            // Reads the encrypted message from the server
            Message response = (Message) in.readObject();
            // Decrypts the message using the shared secret key
            byte[] decryptedMessage = Encryption.decryptMessage(response.getMessage(), sharedSecret.toByteArray(),
                    symmetricAlgorithm, symmetricKey);
            // Verifies the integrity of the decrypted message using the signature
            byte[] computedMac = Integrity.generateDigest(decryptedMessage, sharedSecret.toByteArray());
            if (!Integrity.verifyDigest(response.getSignature(), computedMac)) {
                throw new RuntimeException("The message has been tampered with!");
            }
            //Writes the decrypted message to the console
            System.out.println("Decrypted Message: " + new String(decryptedMessage) + "\n");
            // Writes the decrypted message to the file
            FileHandler.writeFile(this.name + "/files/" + fileName, new String(decryptedMessage).getBytes());
        } catch (StreamCorruptedException e) {
            e.printStackTrace();
        }
    }

    /**
     * Responsible for letting the server know the clients name
     *
     * @param name - name of the client
     * @throws Exception
     */
    public void greeting(String name) throws Exception {
        // Encrypts the message
        byte[] encryptedMessage = Encryption.encryptMessage(name.getBytes(), sharedSecret.toByteArray(),
                symmetricAlgorithm, symmetricKey);
        // Generates the MAC
        byte[] digest = Integrity.generateDigest(name.getBytes(), sharedSecret.toByteArray());
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
     * @throws IOException when an I/O error occurs when sending the message
     */
    public void sendMessage(String filePath) throws Exception {
        this.numOfRequests++;
        // Encrypts the message
        byte[] encryptedMessage = Encryption.encryptMessage(filePath.getBytes(), sharedSecret.toByteArray(),
                symmetricAlgorithm, symmetricKey);
        // Generates the MAC
        byte[] digest = Integrity.generateDigest(filePath.getBytes(), sharedSecret.toByteArray());
        // Creates the message object
        Message messageObj = new Message(encryptedMessage, digest);
        // Sends the message
        out.writeUnshared(messageObj);
        out.flush();
    }

    /**
     * Reads numOfRequestsMap from the file NREQUESTSMAP_PATH , hashMap witch has the users
     * and the respective quantities of requests. If it´s a new user, numOfRequests = 0,
     * otherwise, numOfRequests receives the HasMap corresponding value.
     * @param user
     * @return the number of the user requests
     */
    public int userRegistration(String user) {
        System.out.println();
        MainServer.numOfRequestsMap = FileHandler.readHashMapFromFile(MainServer.NREQUESTSMAP_PATH);
        //FileHandler.printHashMap(MainServer.numOfRequestsMap);
        if (!MainServer.numOfRequestsMap.containsKey(name)) {
            MainServer.numOfRequestsMap.put(name, 0);
            System.out.println("*** Welcome, " + name + "!");
            System.out.println("You are now able to enjoy file storage.");
        } else {
            numOfRequests = MainServer.numOfRequestsMap.get(name);
            System.out.println("*** Welcome again, " + name + "!");
            System.out.println("Number of Requests: " + numOfRequests);
        }
        FileHandler.saveHashMapToTextFile(MainServer.numOfRequestsMap, MainServer.NREQUESTSMAP_PATH); //shouldn't be needed here
        //FileHandler.printHashMap(MainServer.numOfRequestsMap);

        return numOfRequests;
    }

    /**
     * Selecting alternative options of symetric algorythm
     * @return
     */
    public String menuSymmetricAlgorithm() {
        int option;
        do {
            System.out.println("**********************************");
            System.out.println("* Encryption Symmetric Algorithm *");
            System.out.println("* (1)-AES256; (2)-DES; (3)-3DES  *");
            System.out.println("**********************************");
            option = input.nextInt();

            switch (option) {
                case 1:
                    symmetricAlgorithm = "AES";
                    symmetricKey = 256;
                    System.out.println("Implementing AES, key size 256 ...");
                    break;
                case 2:
                    symmetricAlgorithm = "DES";
                    symmetricKey = 64;
                    System.out.println("Implementing DES, key size 56(64) ...");
                    break;
                case 3:
                    symmetricAlgorithm = "DESede";
                    symmetricKey = 192;
                    System.out.println("Implementing 3DES, key size 168 ...");
                    break;
            }
        } while (option < 1 && option > 3);

        return symmetricAlgorithm;
    }

    /**
     * Selecting alternative options of hashing algorythm
     * @return
     */
    public String menuHashingAlgorithm() {
        int option;
        do {
            System.out.println("***********************************");
            System.out.println("*        Hashing Algorithm        *");
            System.out.println("* (1)-MD5; (2)-SHA256; (3)-SHA512 *");
            System.out.println("***********************************");
            option = input.nextInt();

            switch (option) {
                case 1:
                    hashingAlgorithm = "MD5";
                    System.out.println("Implementing MD5, key size 128...");
                    break;
                case 2:
                    hashingAlgorithm = "SHA256";
                    System.out.println("Implementing SHA-3, key size 256...");
                    break;
                case 3:
                    hashingAlgorithm = "SHA512";
                    System.out.println("Implementing SHA-3, key size 512...");
                    break;
            }
        } while (option < 1 && option > 3);
        return hashingAlgorithm;
    }

    public static String getHashingAlgorithm() {
        return hashingAlgorithm;
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