
import static java.lang.System.out;
import java.util.*;
import java.io.*;

import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.spec.*;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.binary.Base64;


public class Crypt {
    public static void  main(String [] args) throws Exception {
        if( args.length != 5 ){
            System.out.println( "Error: usage" );
            System.out.println( "  java Crypt [mode] key key key key" );

            return;
        }

        if( args[0].equals( "-e" ) ){
            encrypt( args[1], args[2], args[3], args[4] );
        }else if( args[0].equals( "-d" ) ){
            decrypt( args[1], args[2], args[3], args[4] );
        }
    } 

    // readBytesFromFile : reads the file into a byte array using Apache's
    // Commons FileUtils library
    public static byte[] readBytesFromFile( String filepath ){
        try{
            byte[] raw_data = org.apache.commons.io.FileUtils.readFileToByteArray( 
                    new java.io.File( filepath ) );

            return raw_data;
        }catch( IOException e ){
            // couldn't read input file, return empty
            return new byte[0];
        }
    }

    // writeBytesToFile : writes the byte array to the given file path using
    // Apache's Commons FileUtils library.  If append is true, this method
    // will append to the given file
    public static void writeBytesToFile( String filepath, byte[] data, boolean append ){
        try{
            org.apache.commons.io.FileUtils.writeByteArrayToFile( 
                    new java.io.File( filepath ), data, append );
        }catch( IOException e ){
            
        }   
    }

    // writeBytesToFile : wrapper for the writeBytesToFile to not append to the end
    // of the file.
    //   Side effects: this will overwrite the file
    public static void writeBytesToFile( String filepath, byte[] data ){
        writeBytesToFile( filepath, data, false );
    }

    // sha256hex : gives the hex string representation of the SHA256 hash of the given String 
    public static String sha256hex( String s ){
        return DigestUtils.sha256Hex( s );
    }

    // sha512hex : gives the hex string representation of the SHA256 hash of the given String
    public static String sha512hex( String s ){
        return DigestUtils.sha512Hex( s );
    }

    // base64encode : encode the byte array into a base64 string
    public static String base64encode( byte[] arr ){
        Base64 base64 = new Base64();
        byte[] str = base64.encode( arr );

        try{
            return new String( str, "UTF-8" );
        }catch( UnsupportedEncodingException e ){
            return new String( str );
        }
    }

    // base64decode : decode the base64 string to a byte array
    public static byte[] base64decode( String str ){
        Base64 base64 = new Base64();
        byte[] bytes;
        try{
            bytes = base64.decode( str.getBytes("UTF-8") );
        }catch( UnsupportedEncodingException e ){
            bytes = base64.decode( str.getBytes() );
        }

        return bytes;
    }

    // generateKeyPair : generates a 1024-bit RSA keypair
    public static KeyPair generateKeyPair(){
        try{
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.genKeyPair();

            return keyPair;
        }catch( Exception e ){
            // Should never throw this exception
            return null;
        }

    }

    // getPrivateKeyFromKeyPair : extracts the PrivateKey from the KeyPair
    public static PrivateKey getPrivateKeyFromKeyPair( KeyPair k ){
        return k.getPrivate();
    }

    // getPublicKeyFromKeyPair : extract the PublicKey from the KeyPair
    public static PublicKey getPublicKeyFromKeyPair( KeyPair k ){
        return k.getPublic();
    }

    // getPrivateKeyFromFile : reads and constructs a PrivateKey from the file
    public static PrivateKey getPrivateKeyFromFile( String pathname ){
        byte[] keyBytes = readBytesFromFile( pathname );

        try{
            // Generate an RSA PrivateKey from the key file
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec( keyBytes );
            KeyFactory kf = KeyFactory.getInstance( "RSA" );

            return kf.generatePrivate( spec );
        }catch( Exception ikse ){
            System.out.println( "Invalid KeySpec exception" );
            return null;
        }
    }

    // getPublicKeyFromFile : reads and constructs a PublicKey from the file
    public static PublicKey getPublicKeyFromFile( String pathname ){
        byte[] keyBytes = readBytesFromFile( pathname );

        return getPublicKeyFromBytes( keyBytes );
    }

    // signData : creates a signature for the data
    //   Note: this utilizes the Java Standard Library java.security.Signature.
    //   It is specified to generate a SHA256 hash of the data and and will 
    //   create a signature with an RSA key
    public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    // verifyData: verifies that the signature on the given byte array
    //   Note: this utilizes the Java Standard Library java.security.Signature
    //   and is specified to verify the signature using an RSA key with a
    //   SHA256 hash
    public static boolean verifyData(byte[] data, byte[] sigBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(sigBytes);
    }

    // generateAESKey : generates the symmetric key that will be used to encrypt
    // the data.
    //   Note: this will generate a 128-bit AES key.
    public static SecretKey generateAESKey(){
        try{
            // Generate an AES key using KeyGenerator with keysize of 128
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);

            SecretKey sKey = keyGen.generateKey(); 

            return sKey;
        }catch( NoSuchAlgorithmException nsae ){
            System.out.println( "  AES algorithm does not exist " + nsae.toString() );
            return null;
        }
    }
    
    // generateIV : generates a random 16 byte initialization vector that will
    // be used in AES CBC encryption
    public static byte[] generateIV(){
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);

        return iv;
    }

    // String wrappers for aes_encrypt and aes_decrypt
    public static String aes_encrypt_s( byte[] plaintext, SecretKey sKey, byte[] iv ){
        byte[] encrypted = aes_encrypt( plaintext, sKey, iv );

        try{
            return new String( encrypted, "UTF-8" );
        }catch( Exception e ){
            return new String( encrypted );
        }
    }

    public static String aes_decrypt_s( byte[] ciphertext, SecretKey sKey, byte[] iv ){
        byte[] deciphered = aes_decrypt( ciphertext, sKey, iv );

        try{
            return new String( deciphered, "UTF-8" );
        }catch( Exception e ){
            return new String( deciphered );
        }
    }

    // aes_encrypt : Encrypt the plaintext with the given secret key
    //   Note: this will use CBC/PKCS5Padding, which is the standard encryption
    //   mode in the Java Standard Library.
    public static byte[] aes_encrypt( byte[] plaintext, SecretKey sKey, byte[] iv ){
        try{
            Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aes.init(Cipher.ENCRYPT_MODE, sKey, new IvParameterSpec( iv ) );

            byte[] ciphertext = aes.doFinal(plaintext);

            return ciphertext;
        }catch( Exception nsae ){
        }
        return new byte[0];
    }

    // aes_decrypt : Decrypt the ciphertext with the given secret key
    //   Note: this will use CBC/PKCS5Padding, which is the standard encryption
    //   mode in the Java Standard Library.
    public static byte[] aes_decrypt( byte[] ciphertext, SecretKey sKey, byte[] iv ){
        try{
            Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");

            aes.init(Cipher.DECRYPT_MODE, sKey, new IvParameterSpec( iv ) );
            byte[] plaintext = aes.doFinal(ciphertext);

            return plaintext;
        }catch( Exception nsae ){
        }
        return new byte[0];
    }

    // rsa_encrypt : encrypt the plaintext using the given public key
    //   Note: this will use ECB/PKCS1Padding, which is the standard encryption
    //   mode in the Java Standard Library
    public static byte[] rsa_encrypt( byte[] plaintext, PublicKey k ){
        try{
            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.ENCRYPT_MODE, k);
            byte[] ciphertext = rsa.doFinal( plaintext );

            return ciphertext;
        }catch( Exception e ){
        }
        return new byte[0];
    }

    // rsa_decrypt : decrypt the plaintext using the given private key
    //   Note: this will use ECB/PKCS1Padding, which is the standard encryption
    //   mode in the Java Standard Library
    public static byte[] rsa_decrypt( byte[] ciphertext, PrivateKey k ){
        try{
            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.DECRYPT_MODE, k);
            byte[] plaintext = rsa.doFinal( ciphertext );

            return plaintext;
        }catch( Exception e ){
        }
        return new byte[0];
    }

    // getEncodedKey : gets the byte encoding of the given secret key
    public static byte[] getEncodedKey( Key sKey ){
        return sKey.getEncoded();
    }

    // getSecretKeyFromBytes : converts a byte array into a 128-bit AES key
    //   Pre.: requires that the encoded key contains at least 128-bits
    public static SecretKey getSecretKeyFromBytes( byte[] encodedKey ){
        SecretKey skey = new SecretKeySpec(encodedKey, 0, 16, "AES");
        
        return skey;
    }

    // getPublicKeyFromBytes : converts a byte array into a 1024-bit RSA key
    public static PublicKey getPublicKeyFromBytes( byte[] encodedKey ){
        try{
            // Generate an RSA PublicKey from the key file
            X509EncodedKeySpec spec = new X509EncodedKeySpec( encodedKey );
            KeyFactory kf = KeyFactory.getInstance( "RSA" );

            return kf.generatePublic( spec );
        }catch( Exception ikse ){
            System.out.println( "Invalid KeySpec exception" );
            return null;
        }
    }

    // encrypt : the main operating function to encrypt the data.
    //   Note: this is where the main logic happens:
    //     1. Read the data, public, and private keys from files
    //     2. Generate a signature of the data
    //     3. Generate a symmetric key
    //     4. Encrypt the data with the symmetric key
    //     5. Encrypt the symmetric key with the public key
    //     6. Bundle all the data and write it to a file
    public static void encrypt( String pubkey_dest, String privkey_orig, String in_file, String out_file ){
        byte[] plaintext = readBytesFromFile( in_file );

        PrivateKey privkey = getPrivateKeyFromFile( privkey_orig );
        PublicKey  pubkey  = getPublicKeyFromFile( pubkey_dest );

        // System.out.println( privkey.toString() );

        // sign the data
        byte[] signature = null;
        try{
            signature = signData( plaintext, privkey );
        }catch( Exception e ){
            System.out.println( "Couldn't sign data" );
        }

        // generate symmetric key and encrypt plaintext with symmetric key
        SecretKey sKey = generateAESKey();
        byte[] iv = generateIV();

        // Encrypt plaintext with symmetric key
        byte[] ciphertext = aes_encrypt( plaintext, sKey, iv );

        // encrypt skey with pubkey_dest

        byte[] skey_encrypted = getEncodedKey( sKey );
        skey_encrypted = rsa_encrypt( skey_encrypted, pubkey );

        // Write the encrypted bytes to the file
        writeBytesToFile( out_file, signature );
        writeBytesToFile( out_file, skey_encrypted, true );
        writeBytesToFile( out_file, iv, true );
        writeBytesToFile( out_file, ciphertext, true );
    }

    // encrypt : the main operating function to encrypt the data.
    //   Note: this is where the main logic happens:
    //     1. Read the data, public, and private keys from files
    //     2. Generate the public and private keys from file
    //     3. Decrypt the symmetric key from the data
    //     4. Decrypt the data with the symmetric key
    //     5. Verify the decrypted data with the signature
    //     6. Write the decrypted data to a file
    public static void decrypt( String privkey_dest, String pubkey_orig, String in_file, String out_file ){
        byte[] raw_data = readBytesFromFile( in_file );

        // signature in first 256 bytes
        // skey in second 256 bytes
        // data in the rest
        
        byte[] ciphersignature = Arrays.copyOfRange( raw_data, 0, 256 );
        byte[] skey_encrypted = Arrays.copyOfRange( raw_data, 256, 512 );
        byte[] iv = Arrays.copyOfRange( raw_data, 512, 528 );
        byte[] ciphertext = Arrays.copyOfRange( raw_data, 528, raw_data.length );

        PrivateKey privkey = getPrivateKeyFromFile( privkey_dest );
        PublicKey  pubkey  = getPublicKeyFromFile( pubkey_orig );

        // decrypt skey with privkey_dest
        byte[] skey_encoded = rsa_decrypt( skey_encrypted, privkey );
        SecretKey skey = getSecretKeyFromBytes( skey_encoded );

        // decrypt data with skey
        byte[] plaintext = aes_decrypt( ciphertext, skey, iv );

        // verify data with pubkey_orig
        try{
            if( verifyData( plaintext, ciphersignature, pubkey ) )
                System.out.println( "verified signature!" );
            else
                System.out.println( "bad signature" );
        }catch( Exception e ){
            System.out.println( "couldn't verify signature" );
        }

        writeBytesToFile( out_file, plaintext );
    }
}
