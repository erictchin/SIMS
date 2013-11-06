
// import static java.lang.System.out;
import java.io.*;
import java.util.*;
import java.net.*;

// import org.json.simple.JSONObject;
import org.json.simple.*;

public class Client {
    PrintWriter out;
    BufferedReader br;

    Socket client;

    public static void main(String [] args) {
    
        String server = args[0]; 
        int port = Integer.parseInt(args[1]);
        try {
            new Client(server, port);
        } catch(Exception e) {
            System.out.println( "Error --> " + e.getMessage());
        }
    }    

    // Construct a Client to handle user input and network communication
    public Client( String ip, int port ) throws Exception {
        client  = new Socket(ip, port);

        br = new BufferedReader( new InputStreamReader( client.getInputStream()) ) ;
        out = new PrintWriter(client.getOutputStream(),true);
        
        // Send the greeting message
        greeting();

        new ChatThread().start();      // create thread to listen for user input
        new MessagesThread().start();  // create thread for listening for messages
    }

    // Abstracted method to generate messages of type with data (used for greeting and message)
    @SuppressWarnings("unchecked")
    public JSONObject generateMessage( String type, String data ){
        JSONObject obj = new JSONObject();

        obj.put( "type", type );
        obj.put( "data", data );

        return obj;
    }
    
    // greeting() : sends a greeting message to the server
    @SuppressWarnings("unchecked")
    public void greeting(){
        JSONObject obj = generateMessage( "greeting", "null" );
        out.println( obj.toString() );
    }

    // message() : sends a MESSAGE message to the server
    @SuppressWarnings("unchecked")
    public void message( String msg ){
        JSONObject obj = generateMessage( "message", msg );

        out.println( obj.toString() );
    }

    // parseMessage() : parses an INCOMING message from the server
    public String parseMessage( String msg ){
        if( msg != null ){
            Object o = JSONValue.parse( msg );
            JSONObject a = (JSONObject) o;

            if( a.get("type").equals("incoming" ) ){
                String ip = (String)a.get("source-ip");
                String port = (String)a.get("source-port");
                String data = (String)a.get("data");

                return String.format( "<from %s:%s>: %s", ip, port, data );
            } 
        }

        return "";
    }
    
    
    // MessagesThread -- waits for messages from server
    class MessagesThread extends Thread {
        public void run() {
            String msg;
            try {
                while(true) {
                    msg = br.readLine();
                    msg = parseMessage( msg );

                    if( msg.length() > 0 ){
                        System.out.println( "\n" + msg );
                        System.out.print( "\n> " );
                    }
                } 
            } catch(Exception e) {}
        }
    }

    // ChatThread -- listens for user input
    class ChatThread extends Thread {
        public void run() {
            String line;

            // Read from STDIN
            java.util.Scanner scan = new java.util.Scanner( System.in );
            System.out.print( "> " );
            try {
                while(true) {
                    line = scan.nextLine();

                    System.out.print( "> " );
                    message( line );
                } 
            } catch(Exception e) { e.printStackTrace() ;}
        }
    }
} 

