
import static java.lang.System.out;
import java.io.*;
import java.util.*;
import java.net.*;

import org.json.simple.*;

public class Server {
  Vector<String> users = new Vector<String>();
  Vector<ClientHandler> clients = new Vector<ClientHandler>();

  // Open a socket on given port to listen for GREETINGs and MESSAGEs
  public void process(int port) throws Exception {
      ServerSocket server = new ServerSocket(port, 10);
      out.println("Server initialized...");
      while( true ) {
          Socket client = server.accept();
          ClientHandler c = new ClientHandler(client);
          if( c.isValid() )
              clients.add(c);
      }
  }

  public static void main(String [] args) throws Exception {
      new Server().process( Integer.parseInt( args[0] ) );
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
     String ip = "";
     String port = "";
     BufferedReader input;
     PrintWriter output;
     boolean valid;

     public ClientHandler( Socket client ) throws Exception {
          // get input and output streams
          input = new BufferedReader( 
              new InputStreamReader( client.getInputStream()) );
          output = new PrintWriter ( client.getOutputStream(), true );

          // Parse the greeting and make sure that it's valid
          if ( parseGreeting( input.readLine() ) ){
              this.ip = client.getInetAddress().getHostAddress();
              this.port = "" + client.getPort();

              valid = true;
              start();
          }else{
              valid = false;
          }
     }

     // Determines if the Client represented by this handler has
     // properly greeted the server.
     public boolean isValid(){
        return this.valid;
     }

     // parseGreeting() : makes sure that the GREETING is correct
     @SuppressWarnings("unchecked")
     public boolean parseGreeting( String line ){
         
         Object o = JSONValue.parse( line );
         JSONObject a = (JSONObject) o;

         if( a.get("type").equals("greeting") ){
            return true;
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

             if( a.get("type").equals("message" ) ){
                 return (String)a.get("data");

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
                 // Read and parse a MESSAGE from the clients
                 message = input.readLine();

                 message = parseMessage(message);

                 // Broadcast messages
                 if( message.length() > 0 ){
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
