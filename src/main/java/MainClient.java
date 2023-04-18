import java.util.Scanner;
public class MainClient {

    public static void main ( String[] args ) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter your name: ");
        String name = scanner.nextLine();
        Client client = new Client ( 8000,name );
        client.execute ( );
    }

}
