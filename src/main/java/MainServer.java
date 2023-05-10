import java.util.HashMap;
import java.util.Scanner;

/**
 * Class that represents the Server and contains the main method
 * Responsible for running the server and stopping the server.
 */
public class MainServer {

    public static final String NREQUESTSMAP_PATH = "server/numOfRequestsMap.txt";
    public static HashMap<String, Integer> numOfRequestsMap = new HashMap<>();
    private static final Scanner scanner = new Scanner(System.in);

    public static void main ( String[] args ) throws Exception {

        FileHandler.createTextFileIfNotExists(NREQUESTSMAP_PATH);
        numOfRequestsMap = FileHandler.readHashMapFromFile(NREQUESTSMAP_PATH);
        System.out.println( "Users recorded: " + numOfRequestsMap.size());
        FileHandler.printHashMap(numOfRequestsMap);

        Server server = new Server ( 8000 );
        Thread serverThread = new Thread ( server );
        serverThread.start ( );

        String stop;
        do {
            stop = scanner.nextLine();
        } while (!stop.equals("s"));

        System.out.println("Stopping the Server...");
        FileHandler.printHashMap(numOfRequestsMap);
        System.out.println("NUMOF: " + numOfRequestsMap);
        FileHandler.saveHashMapToTextFile(numOfRequestsMap, NREQUESTSMAP_PATH);
        System.exit(0);

    }

}
