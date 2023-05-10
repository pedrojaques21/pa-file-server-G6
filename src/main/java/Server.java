import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;

/**
 * This class represents a server that receives a message from the clients. The server is implemented as a thread. Each
 * time a client connects to the server, a new thread is created to handle the communication with the client.
 */
public class Server implements Runnable {
    public static final String FILE_PATH = "server/files";
    private final ServerSocket server;
    private boolean isConnected;

    private BigInteger clientHandlerSharedSecret;

    /**
     * Constructs a Server object by specifying the port number. The server will be then created on the specified port.
     * The server will be accepting connections from all local addresses.
     *
     * @param port the port number
     *
     * @throws IOException if an I/O error occurs when opening the socket
     */
    public Server(int port) throws Exception {
        server = new ServerSocket(port);
        isConnected = true;

    }

    public BigInteger getClientHandlerSharedSecret() {
        return clientHandlerSharedSecret;
    }

    @Override
    public void run() {
        try {
            while (isConnected) {
                Socket client = server.accept();
                process(client);
            }
            closeConnection();
        } catch (RuntimeException | SocketException e) {
            run();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    /**
     * Processes the request from the client.
     *
     * @throws IOException if an I/O error occurs when reading stream header
     */
    private void process(Socket client) throws Exception {
        //creates a thread to answer the client
        ClientHandler clientHandler = new ClientHandler(client);
        clientHandlerSharedSecret = clientHandler.getSharedSecret();
        clientHandler.start();

    }


    /**
     * Closes the connection and the associated streams.
     */
    private void closeConnection() {
        try {
            isConnected = false;
            server.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}