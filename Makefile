all: server client mid

server: server.c
	gcc server.c -o server -lssl -lcrypto -ldl -lpthread -ltommath -ltomcrypt

client: client.c
	gcc client.c -o client -lssl -lcrypto -ldl -lpthread -ltommath -ltomcrypt

mid: mid.c
	gcc mid.c -o mid -lssl -lcrypto -ldl -lpthread -ltommath -ltomcrypt

clean:
	rm server
	rm client
	rm mid