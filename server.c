/*
* @Author: Sun
* @Date:   2020-06-29 14:46:39
* @Last Modified by:   Sun
* @Last Modified time: 2020-07-08 20:36:39
*/

// D-H过程
// 客户端建立连接，计算并发送素数p、原根g、x=g^a mod p
// 服务端接收到p、g、x，生成b并计算y=g^b mod p，将y返回，同时计算出密钥key=x^b mod p
// 客户端收到y，计算出key=y^a mod p

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <tommath.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <pthread.h>
#include "aes.c"

#define SERVER_PORT 10000   // 服务器端口
#define QUEUE_SIZE    10        // 连接数
#define BUFFER_SIZE 1024    // 缓冲区

typedef struct aes_arg
{
    int sockfd;
    struct sockaddr_in client_addr;
    // mp_int aes_key;
    unsigned char aes_iv[32];
    unsigned char aes_tag[16];
    unsigned char aes_key[32];
} aes_arg;

void recv_message(aes_arg *arg)
{
    int sock = arg->sockfd;
    struct sockaddr_in client_addr = arg->client_addr;
    char recv_buffer[512] = {0};
    int recv_n = 0;
    // 接收数据
    while (1)
    {
        recv_n = recv(sock, recv_buffer, 512, 0);
        if (recv_n < 0)    // 接收出错
        {
            printf("客户端 %s:%d 接收消息错误\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
            perror("error: ");
            close(arg->sockfd);
            return;
        }
        else if (recv_n == 0)    //连接关闭
        {
            printf("客户端 %s:%d 连接关闭\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
            close(arg->sockfd);
            return;
        }

        // printf("recv_n: %d\n", recv_n);
        recv_buffer[recv_n] = '\0';
        unsigned int iv_len = 32;
        unsigned int tag_len = 16;
        // unsigned int ct_len=recv_n-iv_len;
        unsigned int ct_len = recv_n - iv_len - tag_len;
        unsigned char plain_text[256] = {0};
        // unsigned char cipher_text[256+tag_len]={0};
        unsigned char cipher_text[256] = {0};
        unsigned char tag[16] = {0};
        unsigned char iv[32] = {0};

        memcpy(iv, recv_buffer, iv_len);
        memcpy(cipher_text, recv_buffer + iv_len, ct_len);
        memcpy(tag, recv_buffer + recv_n - tag_len, tag_len);
        cipher_text[ct_len] = '\0';
        printf("\n来自客户端 %s:%d的消息:\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
        BIO_dump_fp(stdout, recv_buffer, recv_n);
        printf("\niv:\n");
        BIO_dump_fp(stdout, iv, iv_len);
        printf("\ntag:\n");
        BIO_dump_fp(stdout, tag, tag_len);
        printf("\ncipher_text:\n");
        BIO_dump_fp(stdout, cipher_text, ct_len);
        printf("\nkey:\n");
        BIO_dump_fp(stdout, arg->aes_key, 32);
        decrypt(arg->aes_key, plain_text, ct_len, cipher_text, iv, iv_len, tag, tag_len);
        printf("\nplain_text:\n");
        BIO_dump_fp(stdout, plain_text, ct_len);
        printf("\n----------------------------------------------\n");
    }
}

// int send_message(aes_arg *arg)
// {
//     unsigned char plain_text[256] = {0};
//     unsigned char cipher_text[256 + 16] = {0};
//     unsigned char send_buffer[512] = {0};
//     unsigned char tag[16] = {0};
//     printf("\n");
//     scanf("%s", plain_text);
//     // fgets(plain_text, 255, stdin);
//     if (strcmp(plain_text, "quit") == 0)
//     {
//         return 1;
//     }
//     unsigned int pt_len = strlen(plain_text);
//     unsigned int iv_len = 32;
//     unsigned int tag_len = 16;
//     encrypt(arg->aes_key, plain_text, pt_len, cipher_text, arg->aes_iv, iv_len, tag, tag_len);
//     memcpy(cipher_text + pt_len, tag, tag_len);

//     printf("\nplain_text: \n");
//     BIO_dump_fp(stdout, plain_text, pt_len);
//     printf("\ntag: \n");
//     BIO_dump_fp(stdout, tag, tag_len);
//     printf("\ncipher_text: \n");
//     BIO_dump_fp(stdout, cipher_text, pt_len + tag_len);

//     // [iv][ct|tag]
//     memcpy(send_buffer, arg->aes_iv, iv_len);
//     memcpy(send_buffer + iv_len, cipher_text, pt_len + tag_len);
//     send_buffer[iv_len + pt_len + tag_len] = '\0';
//     printf("\nsendbuffer:\n");
//     BIO_dump_fp(stdout, send_buffer, iv_len + pt_len + tag_len);

//     if (send(arg->sockfd, send_buffer, strlen(send_buffer), 0) == -1)
//     {
//         perror("Error ");
//         return -1;
//     }
//     return 0;
// }

// 生成服务器的x、key
void generate_server_key(int sockfd, unsigned char *aes_key)
{
    // 接收客户端发来的p、g、y
    char buffer[BUFFER_SIZE] = {0};
    // 接收p
    recv(sockfd, buffer, BUFFER_SIZE, 0);
    // printf("%s\n", buffer);
    mp_int p;
    mp_init(&p);
    mp_read_radix(&p, buffer, 10);
    // 接收g
    recv(sockfd, buffer, BUFFER_SIZE, 0);
    // printf("%s\n", buffer);
    mp_int g;
    mp_init(&g);
    mp_read_radix(&g, buffer, 10);
    // 接收y
    recv(sockfd, buffer, BUFFER_SIZE, 0);
    mp_int y;
    mp_init(&y);
    mp_read_radix(&y, buffer, 10);

    // 生成服务器的私钥a
    mp_int a;
    mp_init(&a);
    mp_rand(&a, p.used);
    // 计算服务器的公钥x
    mp_int x;
    mp_init(&x);
    mp_exptmod(&g, &a, &p, &x);    // x=g^a mod p
    // 发送x给客户端
    mp_toradix(&x, buffer, 10);
    send(sockfd, buffer, strlen(buffer) + 1, 0);    // 发送x
    // 计算key=y^a mod p
    mp_int key;
    mp_init(&key);
    mp_exptmod(&y, &a, &p, &key);
    mp_toradix(&key, buffer, 16);
    // printf("\nkey: %s\n", buffer);
    // 填充aes_key
    int i = 0;
    for (i = 0; i < 64; ++i)
    {
        if (buffer[i] >= 'A' && buffer[i] <= 'F')
            buffer[i] = buffer[i] - 55;    // 10-16
        if (buffer[i] >= '1' && buffer[i] <= '9')
            buffer[i] = buffer[i] - 48;    // 0-9
    }
    for (i = 0; i < 32; ++i)    // 十六进制 0xXX
        aes_key[i] = buffer[2 * i] * 16 + buffer[2 * i + 1];
}

// 线程函数
void *ex_message(aes_arg *arg)
{
    printf("新线程建立...\n");
    // while(1)
    // {
    recv_message(arg);
    // int ret=send_message(arg);
    // if(ret==-1)
    // break;
    // }
    // close(arg->sockfd);
    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("请输入正确的命令行参数 命令格式： ./server [SERVER_IP_ADDRESS]\n");
        exit(-1);
    }
    int server_sockfd, client_sockfd;
    // 创建TCP套接字
    if ((server_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Error ");
        close(server_sockfd);
        exit(-1);
    }
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));    // 初始化
    server_addr.sin_addr.s_addr = inet_addr(argv[1]);    // IP地址(命令行的第二个参数)
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    // 绑定端口
    if (bind(server_sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
    {
        perror("Error ");
        close(server_sockfd);
        exit(-1);
    }
    printf("服务器绑定至%s\n", inet_ntoa(server_addr.sin_addr));
    // 监听
    listen(server_sockfd, QUEUE_SIZE);
    printf("服务器启动，等待客户端连接...\n");
    while (1)
    {
        unsigned char aes_iv[32];
        unsigned char aes_tag[16];
        unsigned char aes_key[32];
        unsigned char buf[512];
        // mp_int aes_key;
        // mp_init(&aes_key);
        struct sockaddr_in client_addr;    // 保存客户端addr
        socklen_t client_addr_len = sizeof(client_addr);
        if ((client_sockfd = accept(server_sockfd, (struct sockaddr *) &client_addr, &client_addr_len)) < 0)
        {
            perror("Error ");
            exit(-1);
        }
        printf("客户端 %s:%d 连接成功\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
        generate_server_key(client_sockfd, aes_key);
        // BIO_dump_fp(stdout, buf, 32);
        // 接收客户端发送的iv
        recv(client_sockfd, aes_iv, sizeof(aes_iv), 0);
        // 接收客户端发送的tag
        recv(client_sockfd, aes_tag, sizeof(aes_tag), 0);
        printf("\n密钥:\n");
        BIO_dump_fp(stdout, aes_key, 32);    // 输出32字节的密钥
        printf("\n初始向量:\n");
        BIO_dump_fp(stdout, aes_iv, 32);
        // printf("\n附加验证数据:\n");
        // BIO_dump_fp(stdout, aes_tag, 16);

        struct aes_arg for_thread;    // 子线程中用的变量
        for_thread.sockfd = client_sockfd;
        for_thread.client_addr = client_addr;
        // mp_init_copy(&for_thread.aes_key, &aes_key);
        memcpy(for_thread.aes_key, aes_key, sizeof(aes_key));
        memcpy(for_thread.aes_iv, aes_iv, sizeof(aes_iv));
        memcpy(for_thread.aes_tag, aes_tag, sizeof(aes_tag));

        pthread_t thread_new;
        pthread_create(&thread_new, NULL, (void *) ex_message, (void *) &for_thread);    // 创建线程
        pthread_detach(thread_new);    // 收回线程资源
    }
    close(server_sockfd);
    return 0;
}
