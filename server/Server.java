
import static java.lang.System.out;
import java.io.*;
import java.util.*;
import java.net.*;

import javax.crypto.*;
import java.security.*;

import org.json.simple.*;

public class Server {
    // Keep track of the clients connected
    Vector<ClientHandler> clients;

    // Also keep track of essential information:
    //    - map a "name" to associated ClientHandler
    HashMap<String, ClientHandler> usertable;

    // Holds a list of JSON Strings with client information
    HashMap<String, String> client_info;

    // The server's privat ekey
    private PrivateKey serverPrivateKey;

    // The password database
    HashMap<String, String> database;

    // A SecureRandom to generate NONCE challenges for newly authenticating users
    SecureRandom random;

    public static void main(String [] args) throws Exception {

        Server server = new Server();

        server.process( Integer.parseInt( args[0] ) );
    }

    // getPasswordDatabase:
    //   Creates a HashMap that maps between user and password
    private static HashMap<String, String> getPasswordDatabase(){
        HashMap<String, String> db = new HashMap<String, String>();
        try{
            java.util.Scanner scan = new java.util.Scanner( new File( "pw.db" ) );

            while( scan.hasNextLine() ){
                String[] line = scan.nextLine().split(" ");

                db.put( line[0], line[1] );
            }
        }catch(IOException e){}

        return db;
    }

    public Server(){
        this.clients = new Vector<ClientHandler>();
        this.usertable = new HashMap<String, ClientHandler>();
        this.database = Server.getPasswordDatabase();

        this.serverPrivateKey = Crypt.getPrivateKeyFromFile( "server_key" );

        this.random = new SecureRandom();

        this.client_info = new HashMap<String, String>();

    }

    // server_get_password : get the password of the given username
    private String server_get_password( String name ){
        return this.database.get( name );
    }

    // server_get_nonce : generate a SecureRandom NONCE
    private Integer server_get_nonce(){
        byte[] r = new byte[4];
        random.nextBytes(r);

        return new Integer(Math.abs(java.nio.ByteBuffer.wrap(r).getInt()));
    }

    // Open a socket on given port to listen for GREETINGs and MESSAGEs
    public void process(int port) throws Exception {
        ServerSocket server = new ServerSocket(port, 10);
        out.println("Server initialized...");
        while( true ) {
            Socket client = server.accept();
            ClientHandler c = new ClientHandler(client);
            if( c.isValid() ){
                // if the client is valid, then we can:
                // 1. add it to the list of clients
                // 2. add it to the usertable
                this.clients.add(c);
                this.usertable.put( c.getClientName(), c );
                this.client_info.put( c.getClientName(), c.getClientInfo() );
                c.update_client_list(this.all_client_info());
            }
        }
    }

    // Returns a list of all of the connected clients with their client_info
    @SuppressWarnings("unchecked")
    public String all_client_info(){
        java.util.LinkedList<String> info = new java.util.LinkedList<String>();
        info.addAll( this.client_info.values() );

        return JSONValue.toJSONString(info);
    }

    private boolean server_verify_password( String name, String pw_hash, String pw_salt ){
        String verify_pwh = Crypt.sha256hex( pw_salt + server_get_password( name ) );

        return pw_hash.equals( verify_pwh );
    } 


    // broadcast -- sends the message to all users
    public void broadcast( ClientHandler sender, String message ) {
        for ( ClientHandler c : clients )
            // if( ! sender.equals( c ) )
            c.sendMessage( message );
    }

    // ClientHandler : an object to represent each Client connected to
    // the server.
    class ClientHandler extends Thread {
        String name = "";
        String ip = "";
        String port = "";
        PublicKey publicKey;
        SecretKey sessionKey;
        BufferedReader input;
        PrintWriter output;
        boolean valid;
        
        public String getClientPublicKey(){
            byte[] pk_bytes = Crypt.getEncodedKey( this.publicKey );
            String pk_string = Crypt.base64encode( pk_bytes );

            return pk_string;
        }


        @SuppressWarnings("unchecked")
        public String getClientInfo(){
            JSONObject obj = new JSONObject();

            obj.put( "ip", this.ip );
            obj.put( "port", this.port );
            obj.put( "name", this.name );
            obj.put( "key", this.getClientPublicKey() );

            return obj.toString();
        }

        public ClientHandler( Socket client ) throws Exception {
            // get input and output streams
            input = new BufferedReader( 
                    new InputStreamReader( client.getInputStream()) );
            output = new PrintWriter ( client.getOutputStream(), true );

            if( authenticate( input.readLine() ) ){
                System.out.println( "+ Authentication successful for: " + this.name );
                this.ip = client.getInetAddress().getHostAddress();
                this.port = "" + client.getPort();

                // send response to greeting
                if( challenge() ){
                    System.out.println( "validated client confirmation" );
                    valid = true;

                    start();
                }else{
                    valid = false;
                }
            }else{
                valid = false;
            }
        }

        public String getClientName(){
            return this.name;
        }

        // Determines if the Client represented by this handler has
        // properly greeted the server.
        public boolean isValid(){
            return this.valid;
        }

        @SuppressWarnings("unchecked")
        private void send_challenge(String n){
            JSONObject obj = new JSONObject();

            obj.put("type", "greeting");
 
            byte[] nonce = Crypt.rsa_encrypt( n.getBytes(), this.publicKey );
            obj.put("d1", Crypt.base64encode(nonce) );

            JSONObject challenge_data = new JSONObject();
            {
                String salt = Crypt.base64encode( Crypt.generateIV() );
                String pwh = Crypt.sha512hex( salt + server_get_password( this.name ) );

                challenge_data.put( "pwh", pwh );
                challenge_data.put( "salt", salt );

                byte[] challenge_data_salt = Crypt.generateIV();
                byte[] encrypted_challenge_data = Crypt.aes_encrypt(
                        challenge_data.toString().getBytes(),
                        this.sessionKey,
                        challenge_data_salt );

                obj.put( "d2", Crypt.base64encode( encrypted_challenge_data ) );
                obj.put( "d2salt", Crypt.base64encode( challenge_data_salt ) );
            }   
 
            output.println( obj.toString() );
        }

        @SuppressWarnings("unchecked")
        public void update_client_list(String clientInfoString)
        {
            try{
                JSONObject obj = new JSONObject();
                byte[] iv = Crypt.generateIV();
                byte[] encrypted_info_b = Crypt.aes_encrypt(clientInfoString.getBytes(), this.sessionKey, iv );
                String encrypted_info = Crypt.base64encode( encrypted_info_b );

                String sig = Crypt.base64encode( Crypt.generateMAC(clientInfoString.getBytes(), this.sessionKey ) );

                obj.put( "type", "list" );
                obj.put( "data", encrypted_info );
                obj.put( "sig", sig );
                obj.put( "iv", Crypt.base64encode(iv) );

                sendMessage(obj.toString());
            }catch(Exception e){
                System.out.println( "Could not update client list" );
            }  
        }

        // challenge(): send a GREETING challenge to the connecting client to authenticate
        // user
        @SuppressWarnings("unchecked")
        public boolean challenge(){
            Integer n = server_get_nonce();
            String nonce = "" + n;
            send_challenge(nonce);

            if( validate_client_confirmation( nonce ) ){
                return true;
            }else{
                return false;
            }
        }

        // Listens for user to respond to challenge and verifies that the NONCE hash received
        // matches the NONCE hash that server generates
        @SuppressWarnings("unchecked")
        private boolean validate_client_confirmation( String nonce ){
            String nonce_h = Crypt.sha512hex( nonce );

            try{
                String challenge = input.readLine();
                Object o = JSONValue.parse( challenge );
                JSONObject a = (JSONObject) o;

                if( ((String) a.get( "type" )).equals( "confirm" ) ){
                    return nonce_h.equals( (String)a.get("d1") );
                }else{
                    return false;
                }
            }catch( IOException e ){
                return false;
            }
        }

        // authenticate() : makes sure that the GREETING is correct
        //   * check GREETING
        //   * parse data (identity, symmetric key, password)
        @SuppressWarnings("unchecked")
        public boolean authenticate( String line ){

            Object o = JSONValue.parse( line );
            JSONObject a = (JSONObject) o;

            if( a.get("type").equals("greeting") ){
                this.name     = (String)a.get("name");

                // Get the RSA-encrypted session key
                {
                    String encoded_data = (String) a.get("d1");
                    byte[] encrypted_data = Crypt.base64decode( encoded_data );
                    byte[] encoded_key = Crypt.rsa_decrypt( encrypted_data, serverPrivateKey );

                    this.sessionKey = Crypt.getSecretKeyFromBytes( encoded_key );
                }

                // Use the session key to decrypt the rest of the data
                {
                    String encoded_data = (String) a.get("d2");
                    byte[] encrypted_data = Crypt.base64decode( encoded_data );

                    String encoded_salt = (String) a.get("d2salt");
                    byte[] salt = Crypt.base64decode( encoded_salt );

                    byte[] decrypted_data = Crypt.aes_decrypt( encrypted_data, this.sessionKey, salt );

                    String client_data = new String( decrypted_data );

                    Object client_o = JSONValue.parse( client_data );
                    JSONObject client_json = (JSONObject) client_o;

                    byte[] publicKey = Crypt.base64decode( (String) client_json.get("pk") );
                    this.publicKey = Crypt.getPublicKeyFromBytes( publicKey );

                    String pw_salt = (String) client_json.get("salt");
                    String pw_hash = (String) client_json.get("pwh" );

                    return server_verify_password( this.name, pw_hash, pw_salt );
                }
            }else{
                return false;
            }
        }

        // parseMessage() : parse the message and return the "data" blob
        @SuppressWarnings("unchecked")
        public String parseMessage( String line ){
            if( line != null ){
                Object o = JSONValue.parse( line );
                JSONObject a = (JSONObject) o;

                if( a.get("type").equals("list" ) ){

                    System.out.println( "send the user the list again" );
                    this.update_client_list( all_client_info() );
                    
                    return "";

                }else{
                    // client didn't send a proper message
                    return "";
                }
            }else{
                return "";
            }
        }

        // generateBroadcast() : generate an INCOMING message with the given
        // message to broadcast to all Clients
        @SuppressWarnings("unchecked")
        public String generateBroadcast( String msg ){
            JSONObject obj = new JSONObject();

            obj.put( "source-ip", this.ip );
            obj.put( "source-port", this.port );
            obj.put( "type", "incoming" );
            obj.put( "data", msg );

            return obj.toString();
        }

        public void sendMessage( String msg ) {
            output.println( msg );
        }

        public void disconnect(){
            clients.remove( this );
        }

        public void run()  {
            String message;
            try {
                while(true)   {
                    // Read and parse a MESSAGE from the client
                    message = input.readLine();

                    message = parseMessage(message);

                    // Broadcast messages
                    if( message.length() > 0 ){
                        // need to parse
                        message = generateBroadcast(message);

                        System.out.println( "INCOMING: " + message );
                        broadcast(this, message); 
                    }
                }
            } catch(Exception ex) {
                ex.printStackTrace();
            }
        }
    }
}
