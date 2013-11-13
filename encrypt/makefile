
build:
	javac -cp ../libs/commons-io.jar:../libs/commons-codec.jar Crypt.java

encrypt:
	java -cp ../libs/commons-io.jar:../libs/commons-codec.jar: Crypt -e keys/destpub.der keys/origpriv.der orig_plain encrypted_data

decrypt:
	java -cp ../libs/commons-io.jar:../libs/commons-codec.jar: Crypt -d keys/destpriv.der keys/origpub.der encrypted_data decrypted_data

clean:
	rm -rf *.class
	rm -f decrypted_data
	rm -f encrypted_data

genkeys:
	openssl genrsa -out keys/destpriv.pem 2048
	openssl pkcs8 -topk8 -inform PEM -outform DER -in keys/destpriv.pem -out keys/destpriv.der -nocrypt
	openssl rsa -in keys/destpriv.pem -pubout -outform DER -out keys/destpub.der
	openssl genrsa -out keys/origpriv.pem 2048
	openssl pkcs8 -topk8 -inform PEM -outform DER -in keys/origpriv.pem -out keys/origpriv.der -nocrypt
	openssl rsa -in keys/origpriv.pem -pubout -outform DER -out keys/origpub.der

cleankeys:
	rm keys/*


