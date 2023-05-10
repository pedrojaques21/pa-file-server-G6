import java.util.Scanner;

/**
 * Class that represents the clients and contains the main method
 */
public class MainClient {

    public static void main ( String[] args ) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter your name: ");
        String name = scanner.nextLine();
        Client client = new Client ( 8000, name, "User", "User" );
        client.execute();
    }

}
