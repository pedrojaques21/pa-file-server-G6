import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

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
     * @throws IOException when an I/O error occurs when reading the file
     */
    public static byte[] readFile ( String path ) throws IOException {
        File file = new File ( path );
        byte[] fileBytes = new byte[ ( int ) file.length ( ) ];
        FileInputStream fileInputStream = new FileInputStream ( file );
        fileInputStream.read ( fileBytes );
        fileInputStream.close ( );
        return fileBytes;
    }

    /**
     * Writes a text file and returns the result in bytes
     */
    public static void writeFile ( String path , byte[] content ) throws IOException {
        File file = new File ( path );
        FileOutputStream fileOutputStream = new FileOutputStream ( file );
        fileOutputStream.write ( content );
        fileOutputStream.close ( );
    }


}
