import java.io.IOException;
import java.util.HashMap;
import java.util.Scanner;

public class MainServer {

    public static final String NREQUESTSMAP_PATH = "server/numOfRequestsMap.txt";
    public static HashMap<String, Integer> numOfRequestsMap = new HashMap<>();

    private static Scanner scanner = new Scanner(System.in);

    public static void main ( String[] args ) throws Exception {

        FileHandler.createTextFileIfNotExists(NREQUESTSMAP_PATH);
        numOfRequestsMap = FileHandler.readHashMapFromFile(NREQUESTSMAP_PATH);
        System.out.println( "Users recorded: " + numOfRequestsMap.size());
        FileHandler.printHashMap(numOfRequestsMap);

        Server server = new Server ( 8000 );
        Thread serverThread = new Thread ( server );
        serverThread.start ( );

        // move to process() in Server class
        String stop = "";
        do {
            //in Server class, run() method it's coded a clarifying Message.
            stop = scanner.nextLine();
        } while (!stop.equals("s"));

        System.out.println("Stopping the Server...");
        FileHandler.printHashMap(numOfRequestsMap);
        FileHandler.saveHashMapToTextFile(numOfRequestsMap, NREQUESTSMAP_PATH);
        System.exit(0);

    }


}
