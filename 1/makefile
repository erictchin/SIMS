
build:
	javac -cp ./json-simple-1.1.1.jar Client.java
	javac -cp ./json-simple-1.1.1.jar Server.java

server:
	java -cp ./json-simple-1.1.1.jar: Server 9791

client:
	java -cp ./json-simple-1.1.1.jar: Client 127.0.0.1 9791
	
clean:
	rm -rf *.class
