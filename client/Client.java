
// import static java.lang.System.out;
import java.io.*;
import java.util.*;
import java.net.*;

import javax.crypto.*;
import java.security.*;

// import org.json.simple.JSONObject;
import org.json.simple.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

public class Client {
    private PrintWriter out;
    private BufferedReader br;

    private Socket client;
    private String name;
    private String password;

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private PublicKey serverKey;
    private SecretKey sessionKey;

    public static void main(String [] args) {
        // Usage: java Client <name> <server ip> <server port>
        String name = args[0];
        String server = args[1]; 
        int port = Integer.parseInt(args[2]);
        // prompt for password
        String password = getUserPassword();
        try {
            new Client(name, server, port, password);
        } catch(Exception e) {
            System.out.println( "Error --> " + e.getMessage());
        }
    }    

    public static String getUserPassword(){
        System.out.print( "Please enter your password: " );
        java.util.Scanner s = new java.util.Scanner( System.in );
        String password = s.nextLine();

        return password;
    }

    // Construct a Client to handle user input and network communication
    public Client( String name, String ip, int port, String password ) throws Exception {
        this.name = name;
        this.password = password;

        // Get the proper keys
        {
            this.serverKey = Crypt.getPublicKeyFromFile( "server_key.pub" );

            KeyPair mykeys = Crypt.generateKeyPair();
            this.publicKey = mykeys.getPublic();
            this.privateKey = mykeys.getPrivate();

            this.sessionKey = Crypt.generateAESKey();
        }

        this.client  = new Socket(ip, port);

        this.br = new BufferedReader( new InputStreamReader( client.getInputStream()) ) ;
        this.out = new PrintWriter(client.getOutputStream(),true);
        
        // Send the greeting message
        greeting();

        // new ChatThread().start();      // create thread to listen for user input
        // new MessagesThread().start();  // create thread for listening for messages
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
        JSONObject obj = new JSONObject();

        obj.put( "type", "greeting" );
        obj.put( "name", this.name );

        // d1: ServerPub-encrypted symmetric key
        {
            byte[] sessionKey_encrypted = Crypt.getEncodedKey( this.sessionKey );
            sessionKey_encrypted = Crypt.rsa_encrypt( sessionKey_encrypted, this.serverKey );

            String skey_encrypted = Crypt.base64encode( sessionKey_encrypted );
            obj.put( "d1", skey_encrypted );
        }

        // d2: encrypted client data: { public key, password hash, salt }
        JSONObject client_data = new JSONObject();
        {
            // need to encode my public key
            byte[] publicKey_bytes = Crypt.getEncodedKey( this.publicKey );
            String publicKey_string = Crypt.base64encode( publicKey_bytes );

            // need a hash of my password with a salt
            String salt = Crypt.base64encode( Crypt.generateIV() );
            String pwh = Crypt.sha256hex( salt + password );

            client_data.put( "pk", publicKey_string );
            client_data.put( "pwh", pwh );
            client_data.put( "salt", salt );
        }
        byte[] client_data_salt = Crypt.generateIV();
        byte[] encrypted_client_data = Crypt.aes_encrypt( 
                client_data.toString().getBytes(),
                this.sessionKey,
                client_data_salt );

        obj.put( "d2", Crypt.base64encode( encrypted_client_data ) );
        obj.put( "d2salt", Crypt.base64encode( client_data_salt ) );

        // Send the initial JSON blob to the server
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

