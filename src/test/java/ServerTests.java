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
    public void tearDown() throws Exception{
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
    public void checkHandShake(){
        String clientSharedSecret = String.valueOf(client.getSharedSecret());
        String serverSharedSecret = String.valueOf(server.getClientHandlerSharedSecret());
        assertEquals(clientSharedSecret,serverSharedSecret);
    }

    /*@Test
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

    }*/


}