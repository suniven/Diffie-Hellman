all: server client mid server-pro client-pro

server: server.c
	gcc server.c -o server -lssl -lcrypto -ldl -lpthread -ltommath -ltomcrypt

client: client.c
	gcc client.c -o client -lssl -lcrypto -ldl -lpthread -ltommath -ltomcrypt

mid: mid.c
	gcc mid.c -o mid -lssl -lcrypto -ldl -lpthread -ltommath -ltomcrypt

server-pro: server-pro.c
	gcc server-pro.c -o server-pro -lssl -lcrypto -ldl -lpthread -ltommath -ltomcrypt

client-pro: client-pro.c
	gcc client-pro.c -o client-pro -lssl -lcrypto -ldl -lpthread -ltommath -ltomcrypt

clean:
	rm server
	rm client
	rm mid
	rm server-pro
	rm client-pro