import org.junit.jupiter.api.*;

import java.net.Socket;

import static org.junit.jupiter.api.Assertions.*;

public class ServerTests {

    private Client client;
    private static Server server;

    @BeforeAll
    public static void startServer() throws Exception{
        server = new Server ( 8000 );
        Thread serverThread = new Thread(server);
        serverThread.start ( );
    }
    @BeforeEach
    public void setUp() throws Exception{
        client = new Client(8000,"testClient");
    }

    @AfterEach
    public void tearDown() throws Exception {
        client.getClient().close();
    }


    @Test
    @DisplayName("Check if user is created correctly")
    public void createClient() {
        String name = "testClient";
        //Client client = new Client(8000, name);
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
    @DisplayName("Check if handshake is valid")
    public void checkHandShake() {
        String clientSharedSecret = String.valueOf(client.getSharedSecret());
        String serverSharedSecret = String.valueOf(server.getClientHandlerSharedSecret());
        assertEquals(clientSharedSecret, serverSharedSecret);
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
        Client client1 = new Client(8000, "client1");
        client1.sendMessage(requestFile);
        Client client2 = new Client(8000, "client2");
        client2.sendMessage(requestFile);
        assertAll(
                () -> assertNotEquals(client.getSharedSecret(), client1.getSharedSecret()),
                () -> assertNotEquals(client.getSharedSecret(), client2.getSharedSecret()),
                () -> assertNotEquals(client1.getSharedSecret(), client2.getSharedSecret())
        );
    }

    @Test
    @DisplayName("Two clients requesting files at the same time")
    public void differentClientsRequesting() throws Exception{
        String requestFile1 = "GET : hello.txt";
        client.sendMessage(requestFile1);
        Client client1 = new Client(8000,"client1");
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
    public void differentClientsRequestingDifferentFiles() throws Exception{
        String requestFile1 = "GET : hello.txt";
        String requestFile2 = "GET : bye.txt";
        client.sendMessage(requestFile1);
        Client client1 = new Client(8000,"client1");
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
        Client cli = new Client(8000,"Tester");
        String sharedSecretBeforeRenewHandShake = String.valueOf(cli.getSharedSecret());
        String request = "GET : hello.txt";
        cli.sendMessage(request);
        cli.processResponse(request,cli.getIn());
        cli.sendMessage(request);
        cli.processResponse(request,cli.getIn());
        cli.sendMessage(request);
        cli.processResponse(request,cli.getIn());
        cli.sendMessage(request);
        cli.processResponse(request,cli.getIn());
        cli.sendMessage(request);
        cli.processResponse(request,cli.getIn());
        cli.renewHandshake();
        String shareSecretAfterRenewHandShake = String.valueOf(cli.getSharedSecret());
        assertNotEquals(shareSecretAfterRenewHandShake,sharedSecretBeforeRenewHandShake);

    }


}