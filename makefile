
build:
	javac -cp ./libs/json-simple-1.1.1.jar ./client/Client.java
	javac -cp ./libs/json-simple-1.1.1.jar ./server/Server.java

server:
	java -cp ./libs/json-simple-1.1.1.jar: ./server/Server 9791

client:
	java -cp ./libs/json-simple-1.1.1.jar: ./client/Client 127.0.0.1 9791
	
clean:
	rm -rf ./server/*.class
	rm -rf ./client/*.class
