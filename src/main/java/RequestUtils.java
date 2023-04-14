import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RequestUtils {

    public static final String REQUEST_REGEX = "GET : (\\w+.txt)";
    public static final String SERVER_PATH_FILE_FORMAT = "%s/%s";

    /**
     * Computes the absolute path of the file to read from the request.
     *
     * @param request the request from the client
     *
     * @return the path of the file to read
     */
    public static String getAbsoluteFilePath ( String request ) {
        try {
            String fileName = getFileNameFromRequest ( request );
            return String.format ( SERVER_PATH_FILE_FORMAT , Server.FILE_PATH , fileName );
        } catch ( IllegalArgumentException e ) {
            throw new IllegalArgumentException ( "Invalid request" );
        }
    }

    /**
     * Extracts the name of the file from the request.
     *
     * @param request the request from the client
     *
     * @return the name of the requested file
     */
    public static String getFileNameFromRequest ( String request ) {
        Pattern pattern = Pattern.compile ( REQUEST_REGEX );
        Matcher matcher = pattern.matcher ( request );
        boolean matchFound = matcher.find ( );
        if ( matchFound ) {
            return matcher.group ( 1 );
        }
        throw new IllegalArgumentException ( "Invalid request" );
    }

}
