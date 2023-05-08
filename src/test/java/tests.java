import org.junit.jupiter.api.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.net.Socket;
import java.util.Scanner;
import static org.junit.jupiter.api.Assertions.*;

public class tests {

    private Client client;
    private static Server server;

    private static Thread serverThread;


    @BeforeAll
    public static void startServer() throws Exception {
        server = new Server(8000);
        serverThread = new Thread(server);
        serverThread.start();
    }

    @BeforeEach
    public void setUp() throws Exception {
        client = new Client(8000, "TestingClient", "AES", "HmacSHA256");
    }

    @AfterEach
    public void tearDown() throws Exception {
        client.getClient().close();
    }

    @Test
    @DisplayName("Check if handshake is valid")
    public void AAcheckHandShake() { //name starts with AA to be the frist test being executed
        String clientSharedSecret = String.valueOf(client.getSharedSecret());
        String serverSharedSecret = String.valueOf(server.getClientHandlerSharedSecret());
        assertEquals(clientSharedSecret, serverSharedSecret);
    }

    @Test
    @DisplayName("Check if user is created correctly")
    public void createClient() {
        String name = "TestingClient";
        String clientName = client.getName();
        Socket clientScoket = client.getClient();
        assertAll(
                () -> assertEquals(name, clientName),
                () -> assertTrue(clientScoket.isBound())
        );
    }

    @Test
    @DisplayName("Check if keys from handshake are valid")
    public void testHandshake() {
        assertAll(
                () -> assertNotNull(client.getPublicRSAKey()),
                () -> assertNotNull(client.getPrivateRSAKey()),
                () -> assertNotNull(client.getServerPublicRSAKey()),
                () -> assertNotNull(client.getSharedSecret())
        );
    }
    @Test
    @DisplayName("Check if message is being received in a encrypted way")
    public void encryptingMessage() throws Exception {
        File myObj = new File("server/files/hello.txt");
        Scanner myReader = new Scanner(myObj);
        String data = null;
        while (myReader.hasNextLine()) {
            data = myReader.nextLine();
            System.out.println(data);
        }
        myReader.close();
        String request = "GET : hello.txt";
        client.sendMessage(request);
        Message message = new Message(client.getIn().readAllBytes(), client.getSharedSecret().toByteArray());
        String stringMessage = message.toString();
        assertNotEquals(data, stringMessage);
    }

    @Test
    @DisplayName("Check if message received is equal to the requested file")
    public void checkMessageReceived() throws Exception {
        File myObj = new File("server/files/hello.txt");
        Scanner myReader = new Scanner(myObj);
        String data = null;
        while (myReader.hasNextLine()) {
            data = myReader.nextLine();
            System.out.println(data);
        }
        myReader.close();
        String request = "GET : hello.txt";
        client.sendMessage(request);
        byte[] message = client.processResponse(request, client.getIn());
        assertEquals(data, new String(message));
    }


    @Test
    @DisplayName("Check if multiple clients have different handshake values")
    public void differentHandshakeValues() throws Exception {
        String requestFile = "GET : hello.txt";
        client.sendMessage(requestFile);
        Client client1 = new Client(8000, "James", "AES", "HmacSHA256");
        client1.sendMessage(requestFile);
        Client client2 = new Client(8000, "Jared", "AES", "HmacSHA256");
        client2.sendMessage(requestFile);
        assertAll(
                () -> assertNotEquals(client.getSharedSecret(), client1.getSharedSecret()),
                () -> assertNotEquals(client.getSharedSecret(), client2.getSharedSecret()),
                () -> assertNotEquals(client1.getSharedSecret(), client2.getSharedSecret())
        );
    }

    @Test
    @DisplayName("Two clients requesting files at the same time")
    public void differentClientsRequesting() throws Exception {
        String requestFile1 = "GET : hello.txt";
        client.sendMessage(requestFile1);
        Client client1 = new Client(8000, "Joe", "AES", "HmacSHA256");
        client1.sendMessage(requestFile1);
        byte[] message1 = client.processResponse(requestFile1, client.getIn());
        byte[] message2 = client1.processResponse(requestFile1, client1.getIn());
        String stringMessage1 = new String(message1);
        String stringMessage2 = new String(message2);
        assertAll(
                () -> assertNotNull(stringMessage1),
                () -> assertNotNull(stringMessage2),
                () -> assertEquals(stringMessage1, stringMessage2)
        );
    }

    @Test
    @DisplayName("Two clients requesting different files at the same time")
    public void differentClientsRequestingDifferentFiles() throws Exception {
        String requestFile1 = "GET : hello.txt";
        String requestFile2 = "GET : bye.txt";
        client.sendMessage(requestFile1);
        Client client1 = new Client(8000, "Jared", "AES", "HmacSHA256");
        client1.sendMessage(requestFile2);
        byte[] message1 = client.processResponse(requestFile1, client.getIn());
        byte[] message2 = client1.processResponse(requestFile2, client1.getIn());
        String stringMessage1 = new String(message1);
        String stringMessage2 = new String(message2);
        assertAll(
                () -> assertNotNull(stringMessage1),
                () -> assertNotNull(stringMessage2),
                () -> assertNotEquals(stringMessage1, stringMessage2)
        );
    }

    @Test
    @DisplayName("Check if the handshake is renewed after 5 requests")
    public void handShakeRenewCheck() throws Exception {
        String sharedSecretBeforeRenewHandShake = String.valueOf(client.getSharedSecret());
        String firstAlgorithmUsed = client.getSymmetricAlgorithm();
        String request = "GET : hello.txt";
        client.sendMessage(request);
        client.processResponse(request, client.getIn());
        client.sendMessage(request);
        client.processResponse(request, client.getIn());
        client.sendMessage(request);
        client.processResponse(request, client.getIn());
        client.sendMessage(request);
        client.processResponse(request, client.getIn());
        client.sendMessage(request);
        client.processResponse(request, client.getIn());
        client.renewHandshake("AES", "HmacSHA256");
        String shareSecretAfterRenewHandShake = String.valueOf(client.getSharedSecret());
        assertAll(
                () -> assertNotEquals(shareSecretAfterRenewHandShake, sharedSecretBeforeRenewHandShake),
                () -> assertEquals(firstAlgorithmUsed, client.getSymmetricAlgorithm())
        );

    }

    @Test
    @DisplayName("Check if symmetric algorithm is swapped after handshake is renewed")
    public void handShakeRenewAlgChange() throws Exception {
        String sharedSecretBeforeRenewHandShake = String.valueOf(client.getSharedSecret());
        String firstAlgorithmUsed = client.getSymmetricAlgorithm();
        String request = "GET : hello.txt";
        client.sendMessage(request);
        client.processResponse(request, client.getIn());
        client.sendMessage(request);
        client.processResponse(request, client.getIn());
        client.sendMessage(request);
        client.processResponse(request, client.getIn());
        client.sendMessage(request);
        client.processResponse(request, client.getIn());
        client.sendMessage(request);
        client.processResponse(request, client.getIn());
        client.renewHandshake("DES", "HmacSHA256");
        String shareSecretAfterRenewHandShake = String.valueOf(client.getSharedSecret());
        assertAll(
                () -> assertNotEquals(shareSecretAfterRenewHandShake, sharedSecretBeforeRenewHandShake),
                () -> assertNotEquals(firstAlgorithmUsed, client.getSymmetricAlgorithm())
        );
    }

    @Test
    @DisplayName("Check if hashing algorithm is swapped after handshake is renewed")
    public void handShakeRenewHashChange() throws Exception {
        String sharedSecretBeforeRenewHandShake = String.valueOf(client.getSharedSecret());
        String firstAlgorithmUsed = client.getHashingAlgorithm();
        String request = "GET : hello.txt";
        client.sendMessage(request);
        client.processResponse(request, client.getIn());
        client.sendMessage(request);
        client.processResponse(request, client.getIn());
        client.sendMessage(request);
        client.processResponse(request, client.getIn());
        client.sendMessage(request);
        client.processResponse(request, client.getIn());
        client.sendMessage(request);
        client.processResponse(request, client.getIn());
        client.renewHandshake("AES", "HmacSHA512");
        String shareSecretAfterRenewHandShake = String.valueOf(client.getSharedSecret());
        assertAll(
                () -> assertNotEquals(shareSecretAfterRenewHandShake, sharedSecretBeforeRenewHandShake),
                () -> assertNotEquals(firstAlgorithmUsed, client.getHashingAlgorithm())
        );
    }

    @Test
    @DisplayName("Check if long files are sent correctly")
    public void testLongFiles() throws Exception {
        File myObj = new File("server/files/cleancode.txt");
        Scanner myReader = new Scanner(myObj);
        StringBuilder data = new StringBuilder();
        while (myReader.hasNextLine()) {
            String line = myReader.nextLine();
            data.append(line).append(System.lineSeparator());
            System.out.println(line);
        }
        myReader.close();
        String request = "GET : cleancode.txt";
        client.sendMessage(request);
        byte[] message = client.processResponse(request, client.getIn());
        assertEquals(data.toString(), new String(message));
    }



}