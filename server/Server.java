
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
    private void process(int port) throws Exception {
        ServerSocket server = new ServerSocket(port, 10);
        out.println("Server initialized...");
        while( true ) {
            Socket client = server.accept();
            ClientHandler c = new ClientHandler(client);
            if( c.isValid() ){
                // if the client is valid, then we can:
                // 1. add it to the list of clients
                // 2. add it to the usertable
                String cName = c.getClientName();

                this.clients.add(c);
                this.usertable.put( cName, c );
                this.client_info.put( cName, c.getClientInfo() );
                this.update_all_clients_lists();
            }else{
                System.out.println( "- could not authenticate user." );
                c.reject();
            }
        }
    }

    // Broadcast an new list of clients to every user
    private void update_all_clients_lists(){
        String client_infos = this.all_client_info();

        for( java.util.Map.Entry<String, ClientHandler> entry : this.usertable.entrySet() ){
            entry.getValue().update_client_list(client_infos);
        }

    }

    // Returns a list of all of the connected clients with their client_info
    @SuppressWarnings("unchecked")
    private String all_client_info(){
        java.util.LinkedList<String> info = new java.util.LinkedList<String>();
        info.addAll( this.client_info.values() );

        return JSONValue.toJSONString(info);
    }

    // Checks to make sure that the user is not already connected to the server
    private boolean server_is_user_connected( String name ){
        return this.usertable.containsKey( name );
    }

    private boolean server_verify_password( String name, String pw_hash, String pw_salt ){
        String verify_pwh = Crypt.sha256hex( pw_salt + server_get_password( name ) );

        return pw_hash.equals( verify_pwh );
    } 


    private void server_log_user_off( ClientHandler h, String name ){
        System.out.println( "logged off user `" + name + "`" );
        this.clients.remove( h );
        this.usertable.remove( name );
        this.client_info.remove( name );

        this.update_all_clients_lists();

        h.terminate();
        try{
            h.join();
        }catch( InterruptedException e ){}
    }

    // broadcast -- sends the message to all users
    private void broadcast( ClientHandler sender, String message ) {
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
        String peer_port = "";
        PublicKey publicKey;
        SecretKey sessionKey;
        BufferedReader input;
        PrintWriter output;
        Socket sock;
        boolean valid;
        private volatile boolean running = true;
        
        public String getClientPublicKey(){
            byte[] pk_bytes = Crypt.getEncodedKey( this.publicKey );
            String pk_string = Crypt.base64encode( pk_bytes );

            return pk_string;
        }

        // returns a stringified JSON object containing ip, port,
        // name, and base64 encoded public key
        @SuppressWarnings("unchecked")
        public String getClientInfo(){
            JSONObject obj = new JSONObject();

            obj.put( "ip", this.ip );
            obj.put( "port", this.port );
            obj.put( "peer_port", this.peer_port);
            obj.put( "name", this.name );
            obj.put( "key", this.getClientPublicKey() );

            return obj.toString();
        }

        public void terminate(){
            try{
                this.sock.close();
            }catch( IOException e ){
            }
        }

        public ClientHandler( Socket client ) throws Exception {
            // get input and output streams
            this.sock = client;
            this.input = new BufferedReader( 
                    new InputStreamReader( client.getInputStream()) );
            this.output = new PrintWriter ( client.getOutputStream(), true );

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

        public void reject(){
            this.output.println( "You could not be authenticated" );
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

        // Given a name (encrypted with the client-server session key, log the user off.
        public void log_user_off( String encrypted_name, String salt ){
            try{
                 // 1. decrypt my username with session key and salt
                 byte[] salt_b = Crypt.base64decode( salt );
                 byte[] name_b = Crypt.base64decode( encrypted_name );

                 byte[] name_d = Crypt.aes_decrypt( name_b, this.sessionKey, salt_b );

                 if( new String( name_d ).equals( this.name ) ){
                    this.running = false;
                    server_log_user_off( this, this.name );
                 }
            }catch( Exception e ){
            }
        }

        //sends current list of valid clients and their information to this client.
        //client_info is a JSON list object as a String
        //client_info data is maintained in Server.client_info
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
                this.name = (String)a.get("name");

                // If the user is already connected, do not authenticate
                if( server_is_user_connected( this.name ) ){
                    return false;
                }

                this.peer_port = (String)a.get("peer_port");

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

                }else if( a.get("type").equals("logoff") ){
                    System.out.println( "user has logged off" );

                    String name = (String) a.get("name");
                    String salt = (String) a.get("salt");
                    this.log_user_off( name, salt );

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
                while(this.running)   {
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
