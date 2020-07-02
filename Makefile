all: server client

server: server.c
	gcc server.c -o server -lssl -lcrypto -ldl -lpthread -ltommath -ltomcrypt

client: client.c
	gcc client.c -o client -lssl -lcrypto -ldl -lpthread -ltommath -ltomcrypt

clean:
	rm server
	rm client