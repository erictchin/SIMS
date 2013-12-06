
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
    private ServerSocket peer_listener;
    private String name;
    private String password;

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private PublicKey serverKey;
    private SecretKey sessionKey_server;
    private SecureRandom random;

    private HashMap<String, Peer> peers;

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

    public String getConnectedUsers(){
        java.lang.StringBuilder strb = new java.lang.StringBuilder();
        String activeFlag = " *";
        String inactiveFlag = "";
        for( java.util.Map.Entry<String, Peer> entry : this.peers.entrySet() ){

            String flag = inactiveFlag;
            if( entry.getValue().isActive() ){
                flag = activeFlag;
            }
            strb.append( "  " + entry.getKey() + flag + "\n" );
        }

        return strb.toString();
    }

    private String client_get_name(){
        return this.name;
    }
    
    public HashMap<String, Peer> client_getPeers()
    {
        return this.peers;
    }

    public PublicKey client_get_publicKey() { return this.publicKey; }
    public PrivateKey client_get_privateKey() { return this.privateKey; }
    public Integer client_get_nonce() 
    {
        byte[] r = new byte[4];
        random.nextBytes(r);
        return new Integer(Math.abs(java.nio.ByteBuffer.wrap(r).getInt()));
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

            this.sessionKey_server = Crypt.generateAESKey();
        }

        this.client  = new Socket(ip, port);
        this.peer_listener = new ServerSocket(0);

        this.br = new BufferedReader( new InputStreamReader( client.getInputStream()) ) ;
        this.out = new PrintWriter(client.getOutputStream(),true);
        this.peers = new HashMap<String, Peer>();
        
        // Send the greeting message
        send_greeting();
        if( receive_greeting() ){
            // Successfully authenticated the server and sent challenge confirmation.
            System.out.println( "Successfully authenticated the server." );
            System.out.println( "Now starting listening threads" );

            new ChatThread().start();      // create thread to listen for user input
            new MessagesThread().start();  // create thread for listening for server messages
            new PeerListener(this.peer_listener).start();    // listen for incoming peer messages
        }else{
            System.out.println( "You could not be authenticated to the server." );
        }   
    }

    // Abstracted method to generate messages of type with data (used for greeting and message)
    @SuppressWarnings("unchecked")
    public JSONObject generateMessage( String type, String data ){
        JSONObject obj = new JSONObject();

        obj.put( "type", type );
        obj.put( "data", data );

        return obj;
    }

    // Generates a logoff message with encrypted name
    @SuppressWarnings("unchecked")
    public JSONObject generateLogoff(){
        JSONObject obj = new JSONObject();

        obj.put( "type", "logoff" );

        byte[] salt = Crypt.generateIV();
        byte[] encrypted_name = Crypt.aes_encrypt(
                this.name.getBytes(),
                this.sessionKey_server,
                salt );

        obj.put( "name", Crypt.base64encode( encrypted_name ) );
        obj.put( "salt", Crypt.base64encode( salt ) );

        System.out.println( obj.toString() );

        return obj;
        
    }

    // We have authenticated the server, so now we need to send the proper
    // confirmation
    @SuppressWarnings("unchecked")
    public void send_authentication_confirm( String nonce ){
        JSONObject obj = new JSONObject();

        obj.put( "type", "confirm" );
        obj.put( "d1", Crypt.sha512hex( nonce ) );

        out.println( obj.toString() );
    }

    @SuppressWarnings("unchecked")
    public boolean receive_greeting(){
        try{
            String server_greeting = br.readLine();
            System.out.println("Received greeting from server: " + server_greeting);
            Object o = JSONValue.parse( server_greeting );
            JSONObject a = (JSONObject) o;

            if( a.get("type").equals("greeting") ){
                // proper message type
                String nonce = (String) a.get("d1");
                {
                    byte[] nonce_b = Crypt.base64decode(nonce);
                    nonce_b = Crypt.rsa_decrypt( nonce_b, this.privateKey );

                    nonce = new String( nonce_b );
                }

                // deal with d2 {pwh, pwh_salt}, salt
                byte[] d2salt = Crypt.base64decode( (String) a.get("d2salt") );
                String d2 = (String)a.get("d2");
                JSONObject challenge_data = null;
                {
                    byte[] d2_b = Crypt.base64decode( d2 );
                    byte[] d2_decrypt = Crypt.aes_decrypt( d2_b, this.sessionKey_server, d2salt );

                    String challenge_data_raw = new String( d2_decrypt );
                    Object cd = JSONValue.parse( challenge_data_raw );
                    challenge_data = (JSONObject) cd;
                }
                String pwh = (String) challenge_data.get("pwh");
                String salt = (String) challenge_data.get("salt");

                // compare sha512hex( salt + this.password ) to PWH
                if( pwh.equals( Crypt.sha512hex( salt + this.password ) ) ){
                    // send a challenge
                    
                    send_authentication_confirm( nonce );

                    return true;
                }else{
                    return false;
                }
            }else{
                return false;
            }
        }catch(Exception e){
            return false;
        }
    }

    // greeting() : sends a greeting message to the server
    @SuppressWarnings("unchecked")
    public void send_greeting(){
        JSONObject obj = new JSONObject();
        int peer_port = this.peer_listener.getLocalPort();

        obj.put( "type", "greeting" );
        obj.put( "name", this.name );
        obj.put( "peer_port", "" + peer_port);

        // d1: ServerPub-encrypted symmetric key
        {
            byte[] sessionKey_encrypted = Crypt.getEncodedKey( this.sessionKey_server );
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

        // Encrypt the client_data with the symmetric key and a new salt
        {
            byte[] client_data_salt = Crypt.generateIV();
            byte[] encrypted_client_data = Crypt.aes_encrypt( 
                    client_data.toString().getBytes(),
                    this.sessionKey_server,
                    client_data_salt );

            obj.put( "d2", Crypt.base64encode( encrypted_client_data ) );
            obj.put( "d2salt", Crypt.base64encode( client_data_salt ) );
        }

        // Send the initial JSON blob to the server
        out.println( obj.toString() );
    }

    // message() : sends a MESSAGE message to the server
    @SuppressWarnings("unchecked")
    public void message( String msg ){
        JSONObject obj = generateMessage( "message", msg );

        out.println( obj.toString() );
    }

    // update the list of other clients with information from the server
    public boolean updateList( String data, String hmac, String iv_s ){

        try{
            byte[] iv = Crypt.base64decode( iv_s );
            // 1. base64decode data
            byte[] data_b = Crypt.base64decode( data );
            // 2. decrypt data using session key with server
            byte[] decrypted_data = Crypt.aes_decrypt( data_b, this.sessionKey_server, iv );
            // 3. verify signature of decrypted data with hmac
            String client_infos = new String( decrypted_data );

            // calculate hmac and compare it with hmac
            String my_hmac = Crypt.base64encode( Crypt.generateMAC( decrypted_data, this.sessionKey_server ) );

            if( my_hmac.equals( hmac ) ){
                HashMap<String, Peer> newpeers = new HashMap<String, Peer>();
                // confirmed the signature of the data

                // 4. parse client_infos to get the real list
                // parse JSON List [a, b, c...]
                Object obj = JSONValue.parse( client_infos );
                JSONArray arr = (JSONArray) obj;

                for( int i = 0; i < arr.size(); i++ ){
                    String c = (String) arr.get( i );
                    Object cobj = JSONValue.parse( c );
                    JSONObject client = (JSONObject) cobj;

                    String ip = (String) client.get( "ip" );
                    String port = (String) client.get( "port" );
                    String peer_port = (String) client.get( "peer_port" );
                    String name = (String) client.get( "name" );
                    String key_s = (String) client.get( "key" );

                    PublicKey key = Crypt.getPublicKeyFromBytes( Crypt.base64decode( key_s ) );

                    Peer new_peer = new Peer( ip, port, name, peer_port, key );
                    newpeers.put( name, new_peer );
                }

                // make sure that the proper peers are in my peer list.
                // in particular, remove peers that I list but the server doesn't
                // and add peers that the server lists and I don't

                Set<String> currentPeerNames = this.peers.keySet();
                Set<String> newPeerNames = newpeers.keySet();

                for( String n : currentPeerNames ){
                    // for all of my peers, if server doesn't list it, then remove it
                    if( !newPeerNames.contains( n ) ){
                        this.peers.remove( n );
                    }
                }

                for( String n : newPeerNames ){
                    // for all new peers, if i don't have it, then add it
                    if( !this.peers.containsKey( n ) ){
                        this.peers.put( n, newpeers.get( n ) );
                    }
                }

                return true;
            }else{
                return false;
            }
        }catch( Exception e ){
            return false;
        }
    }

    //thread listens to for new peer conversations
    class PeerListener extends Thread {

        private ServerSocket listener;

        public PeerListener(ServerSocket listener)
        {
            this.listener = listener;
        }

        public void run() 
        {
            
            while(true)
            {
                try
                {
                    Socket incoming = listener.accept();
                    PeerAcceptor pa = new PeerAcceptor (incoming); 
                }
                catch (IOException ioe) { }
                

            }
        }

    }
    
    
    class PeerAcceptor 
    {
        Socket new_socket;
        BufferedReader input;
        PrintWriter output;
        
        @SuppressWarnings("unchecked")
        public PeerAcceptor (Socket s)
        {
            try {
                new_socket = s;
                input = new BufferedReader( new InputStreamReader ( new_socket.getInputStream()));
                output = new PrintWriter (new_socket.getOutputStream(), true);
            
                String peer_info = input.readLine();

                Object o = JSONValue.parse( peer_info );
                JSONObject jo = (JSONObject) o;

                Object hs = JSONValue.parse( (String)jo.get("conn_info") );
                JSONObject hs_info = (JSONObject) hs; 

                if( jo.get("type").equals("handshake") )
                {

                    String name = (String)jo.get("name");
                    HashMap<String, Peer> peers = client_getPeers();

                    if(!peers.containsKey(name))
                        this.new_socket.close();

                    if(!peers.get(name).authenticate(hs_info, input, output)) 
                        this.new_socket.close();
                }
            }
            catch (IOException ioe) { }
        }
    }
    
    // MessagesThread -- waits for messages from server
    class MessagesThread extends Thread {
        // parseMessage() : parses an INCOMING message from the server
        @SuppressWarnings("unchecked")
        public String parseMessage( String msg ){
            if( msg != null ){
                Object o = JSONValue.parse( msg );
                JSONObject a = (JSONObject) o;

                if( a.get("type").equals("list" ) ){
                    String data = (String)a.get("data");
                    String hmac = (String)a.get("sig");
                    String iv = (String)a.get("iv");

                    if( updateList( data, hmac, iv) ){
                        String s = "<server>: updated user list:\n" +
                            getConnectedUsers();
                        return s;
                    }
                    String s = "<server>: user list:\n" +
                        getConnectedUsers();
                    return s;
                } 
            }

            return "";
        }
    
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

        public void message( String msg ){
            String test = msg.toLowerCase();
            if( test.startsWith( "list" ) ){

                // then send the server a list command
                
                out.println( generateMessage( "list", "" ) );
            }else if( test.startsWith( "send" ) ){
                int space1 = msg.indexOf( " " );
                int space2 = msg.indexOf( " ", space1+1 );

                String recipient = test.substring( space1, space2 ).trim();
                String message = msg.substring( space2 ).trim();
                
                HashMap<String, Peer> peers = client_getPeers();

                if( peers.containsKey( recipient ) ){
                    Peer receiver = peers.get( recipient );

                    if( receiver.isActive() ){
                        receiver.sendMessage( message );
                        System.out.println( "sent message to " + recipient );
                    }else{
                        receiver.init_handshake();
                        System.out.println( recipient + " is not active" );
                    }
                }else{
                    System.out.println( "  Error: user " + recipient + " is not valid." );
                }


            }else if( test.startsWith( "logout" ) || test.startsWith( "logoff" ) || test.startsWith( "exit" ) ){
                // Perform logout procedure
                // 1. send server logout command
                // 2. tell peers that i've disconnected?
                out.println( generateLogoff() );
            }else if( test.startsWith( "help" ) ){
                String commands = "Possible commands include: \n" +
                    "  * `list` - updates list and displays connected peers\n" +
                    "  * `send <peer> <message>` - sends <message> to peer named <peer>\n" +
                    "  * `logoff` or `logout` or `exit` - will disconnect from the SIMS\n" + 
                    "  * `help` - display this message\n";

                System.out.println( commands );

            }
        }

        public void run() {
            String line;

            // Read from STDIN
            java.util.Scanner scan = new java.util.Scanner( System.in );
            System.out.print( "> " );
            try {
                while(true) {
                    line = scan.nextLine().trim();

                    message( line );
                    System.out.print( "> " );
                } 
            } catch(Exception e) { e.printStackTrace() ;}
        }
    }

    // Peer -- keeps track of an individual peer
    // * Should listen for messages from peer
    // * Should be able to send messages to peer
    class Peer extends Thread
    {
        String name;
        String ip;
        String port;
        String peer_port;

        PublicKey publicKey;
        SecretKey sessionKey;
        
        Socket socket;
        BufferedReader input;
        PrintWriter output;
        boolean active;
        boolean valid;

        public Peer(String ip, String port, String name, String peer_port, PublicKey publicKey )
        {
            this.name = name;
            this.ip = ip;
            this.port = port;
            this.peer_port = port;
            this.publicKey = publicKey;

            this.sessionKey = null;
            this.input = null;
            this.output = null;

            this.active = false;
            this.valid = false;
        }

        //build and send initial handshake information
        // { type : handshake, name : name, conn_info : conn_info }
        // conn_info is { key : PuB{KAB}, nonce : KAB{RA}, iv : iv }
        public boolean init_handshake()
        {
            this.socket = new Socket(this.ip, Integer.parseInt(this.port));
            this.input = new BufferedReader( new InputStreamReader( socket.getInputStream()));
            this.output = new PrintWriter( this.socket.getOutputStream(), true );

            JSONObject obj = new JSONObject();
            JSONObject conn_info = new JSONObject();
            obj.put( "type", "handshake" );
            obj.put( "name", client_get_name() );

            this.sessionKey = Crypt.generateAESKey();
            byte[] encoded_sk = Crypt.getEncodedKey( this.sessionKey );
            byte[] encrypted_sk = Crypt.rsa_encrypt( encoded_sk, this.publicKey );
            conn_info.put( "key", Crypt.base64encode( encrypted_sk );

            byte[] iv = Crypt.generateIV();
            conn_info.put( "iv", base64encode(iv) );

            Integer r = client_get_nonce();
            byte[] ra = base64decode( "" + r );
            byte[] encrypted_nonce = Crypt.aes_encrypt( ra, this.sessionKey, iv ); 
            conn_info.put( "nonce", base64encode(encrypted_nonce) );

            obj.put( "conn_info", conn_info.toString() );

            this.output.println( obj.toString() );

            if(recv_challenge(ra))
                this.valid = true;
        }

        //waits for response from peer 
        //A ← B: PuA{RB}, KAB{h1(RA)} 
        public boolean recv_challenge(byte[] ra)
        {
            try
            {
                String recvbuf = input.readLine();    
                Object o = JSONValue.parse( recvbuf );
                JSONObject jo = (JSONObject) o;

                String type = (String) jo.get("type");
                String encoded_encrypted_rb = (String) jo.get("rb");
                String encoded_ra_salt = (String) jo.get("ra_salt");
                String encoded_encrypted_hashed_ra = (String) jo.get("ra"); 
                
                if(type.equals("peer_challenge"))
                {

                    byte[] encrypted_rb = Crypt.base64decode( encoded_encrypted_rb );
                    byte[] rb = Crypt.rsa_decrypt( encrypted_rb, client_get_privateKey() );

                    byte[] salt = Crypt.base64decode(encoded_ra_salt);
                    byte[] encrypted_hashed_ra = Crypt.base64decode(encoded_encrypted_hashed_ra);
                    
                    byte[] hashed_ra = Crypt.aes_decrypt(encrypted_hashed_ra, this.sessionKey, salt);

                    String enc_ra = Crypt.base64encode(ra);
                    String enc_rb = Crypt.base64encode(rb);
                
                    String my_ra_hash = Crypt.sha256hex( enc_ra );
                
                    if( my_ra_hash.equals(Crypt.base64encode(hashed_ra)))
                        send_nonces(enc_ra, enc_rb);
                }
        }

        public void send_nonces(String ra, String rb)
        {
            JSONObject jo = new JSONObject();
            jo.put( "type", "h3" );
            jo.put( "hash", Crypt.sha256hex( ra + rb) );
            this.output.println( jo.toString() );
        }


        //A → B: PuB{KAB}, KAB{RA} 
        //A ← B: PuA{RB}, KAB{h1(RA)} 
        //A → B: h2(RA, RB)
        @SuppressWarnings("unchecked")
        public boolean challenge_hs(JSONObject hs_info, BufferedReader input, PrintWriter output)
        {
            String encoded_encrypted_skey = (String) hs_info.get("key");
            String encoded_encrypted_nonce = (String) hs_info.get("nonce");

            String encoded_iv = (String) hs_info.get("iv");
            byte[] iv = Crypt.base64decode(encoded_iv);

            byte[] encrypted_skey = Crypt.base64decode( encoded_encrypted_skey );
            byte[] encoded_skey = Crypt.rsa_decrypt(encrypted_skey, client_get_privateKey());

            this.sessionKey = Crypt.getSecretKeyFromBytes( encoded_skey );

            byte[] encrypted_nonce = Crypt.base64decode( encoded_encrypted_nonce );
            byte[] decrypted_nonce = Crypt.aes_decrypt( encrypted_nonce, this.sessionKey, iv );

            boolean valid = challenge(decrypted_nonce, input, output);

            if(valid)
            {
                this.output = output;
                this.input = input;
                this.valid = true;
            }
            return valid;
        }

        public boolean challenge(byte[] nonce, BufferedReader input, PrintWriter output)
        {
            Integer r = client_get_nonce();
            String rb = "" + r;
            String ra = Crypt.base64encode(nonce);
            
            send_challenge(rb, ra, output);
    
            if(validate_challenge(rb, ra, input)) return true;
            else return false;
        }

        @SuppressWarnings("unchecked")
        public void send_challenge(String n, String ra, PrintWriter output)
        {
            JSONObject obj = new JSONObject();
            obj.put("type", "peer_challenge");

            byte[] rb = Crypt.rsa_encrypt( n.getBytes(), this.publicKey );
            obj.put("rb", Crypt.base64encode(rb));

            String hashed_ra = Crypt.sha256hex(ra);
            byte[] iv = Crypt.generateIV();
            byte[] encrypted_ra = Crypt.aes_encrypt(hashed_ra.getBytes(), this.sessionKey, iv);

            obj.put("ra", Crypt.base64encode(encrypted_ra));
            obj.put("ra_salt", Crypt.base64encode(iv));
        
            output.println(obj.toString());
        }

        @SuppressWarnings("unchecked")
        public boolean validate_challenge(String rb, String ra, BufferedReader input)
        {
            String valid_hash = Crypt.sha256hex ( ra + rb );
            try
            {
                String recvbuf = input.readLine();
                Object o = JSONValue.parse( recvbuf );
                JSONObject jo = (JSONObject) o;

                String type = (String) jo.get("type");
                String recv_hash = (String) jo.get("hash");
                
                return type.equals("h3") && recv_hash.equals(valid_hash);
            }
            catch (IOException e) { return false; }
        }

        public void run(){
            // First, set this to active.
            this.active = true;
            String msg;
            try {
                while(active) {
                    msg = this.input.readLine();
                    msg = parseMessage( msg );

                    if( msg.length() > 0 ){
                        System.out.println( "\n<" + this.name + ">: " + msg );
                        System.out.print( "\n> " );
                    }
                } 
            } catch(Exception e) {}
        }

        @SuppressWarnings("unchecked")
        public void sendMessage(String msg){
            JSONObject obj = new JSONObject();

            try{ 
                byte[] salt_b = Crypt.generateIV();
                String encrypted_msg = Crypt.base64encode(
                        Crypt.aes_encrypt( msg.getBytes(), this.sessionKey, salt_b ) );
                String hmac = Crypt.base64encode( Crypt.generateMAC( msg.getBytes(),
                            this.sessionKey ) );

                obj.put( "type", "send" );
                obj.put( "data", encrypted_msg );
                obj.put( "sig", hmac );
                obj.put( "iv", Crypt.base64encode( salt_b ) );


                output.println( obj.toString() );
            }catch(Exception e){
                System.out.println( "Error sending message to <" + this.name + ">." );
            }
        }

        @SuppressWarnings("unchecked")
        public String parseMessage( String msg ){
            if( msg != null ){
                Object o = JSONValue.parse( msg );
                JSONObject a = (JSONObject) o;

                if( a.get("type").equals("send" ) ){
                    String data = (String)a.get("data");
                    String hmac = (String)a.get("sig");
                    String iv_s = (String)a.get("iv");

                    try{
                        byte[] iv = Crypt.base64decode( iv_s );
                        // 1. base64decode data
                        byte[] data_b = Crypt.base64decode( data );
                        // 2. decrypt data using session key with server
                        byte[] decrypted_data = Crypt.aes_decrypt( 
                                data_b, this.sessionKey, iv );
                        // 3. verify signature of decrypted data with hmac
                        String real_data = new String(decrypted_data);

                        // calculate hmac and compare it with hmac
                        String my_hmac = Crypt.base64encode( 
                                Crypt.generateMAC( decrypted_data, this.sessionKey ) );

                        if( my_hmac.equals( hmac ) ){
                            // confirmed the signature of the data

                            return real_data;
                        }
                    }catch(Exception e){}

                } 
            }

            return "";
        }
        public boolean isActive(){
            return this.active;
        }

    }
} 

