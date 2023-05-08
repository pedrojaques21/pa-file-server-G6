import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * This class represents the file handler. It was the methods for reading and writing text files.
 */
public class FileHandler {


    /**
     * Reads a text file and returns the result in bytes.
     *
     * @param path the path of the file to read
     *
     * @return the content of the file in bytes
     *
     */
    public static byte[] readFile(String path) {
        try {
            File file = new File(path);
            if (file.exists()) {
                byte[] fileBytes = new byte[(int) file.length()];
                FileInputStream fileInputStream = new FileInputStream(file);
                fileInputStream.read(fileBytes);
                fileInputStream.close();
                return fileBytes;
            } else {
                String helloString = "ERROR - FILE NOT FOUND";
                return helloString.getBytes(StandardCharsets.UTF_8);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Writes a text file and returns the result in bytes
     */
    public static void writeFile ( String path , byte[] content ) {
        try {
            File file = new File ( path );
            FileOutputStream fileOutputStream = new FileOutputStream ( file );
            fileOutputStream.write ( content );
            fileOutputStream.close ( );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Reads a textFile and returns an HashMap
     *
     * @param requestsFilePath the path of the file to read
     *
     * @return the content of the file in bytes
     */
    public static HashMap<String, Integer> readHashMapFromFile(String requestsFilePath) {
        HashMap<String, Integer> myHashMap = new HashMap<>();
        try {
            BufferedReader reader = new BufferedReader(new FileReader(requestsFilePath));
            String line = reader.readLine();
            while (line != null) {
                String[] parts = line.split(":");
                String key = parts[0].trim();
                Integer value = Integer.parseInt(parts[1].trim());
                myHashMap.put(key, value);
                line = reader.readLine();
            }
            reader.close();
        } catch (IOException e) {
            System.out.println("Error reading the HashMap data from file: " + e.getMessage());
        }
        return myHashMap;
    }

    /**
     * Writes a HashMap to a textFile
     *
     * @param myHashMap the HashMap to write
     *
     * @param filePath the path of the file to write
     */
    public static void saveHashMapToTextFile(HashMap<String, Integer> myHashMap, String filePath) {
        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter(filePath));
            for (Map.Entry<String, Integer> entry : myHashMap.entrySet()) {
                writer.write(entry.getKey() + ":" + entry.getValue());
                writer.newLine();
            }
            System.out.println("HashMap saved...");
            writer.close();
        } catch (IOException e) {
            System.out.println("Error saving the HashMap data to file: " + e.getMessage());
        }
    }

    /**
     * Check if file exists, otherwise creates a new one.
     *
     * @param filePath the path of the file to check
     */
    public static void createTextFileIfNotExists(String filePath) {

        File file = new File(filePath);
        if (!file.exists()) {
            try {
                boolean created = file.createNewFile();
                if (created) {
                    System.out.println("New File " + filePath + " created!");
                }
            } catch (IOException e) {
                System.out.println("Error creating file: " + e.getMessage());
            }
        }
    }

    /**
     * Prints on the console the contents of a HashMap
     *
     * @param myHashMap the HashMap to print
     */
    public static void printHashMap(HashMap<String, Integer> myHashMap) {
        System.out.println("\t\tName\tRequests");
        for (Map.Entry<String, Integer> entry : myHashMap.entrySet()) {
            String tabs = (entry.getKey().length() < 8 ? "\t\t" : "\t");
            if (entry.getKey().length() < 4) tabs = "\t\t\t";
            System.out.println("\t\t" + entry.getKey() + tabs + entry.getValue());
        }
    }


}
