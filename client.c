/*
* @Author: Sun
* @Date:   2020-06-29 14:45:49
* @Last Modified by:   Sun
* @Last Modified time: 2020-07-06 17:48:15
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
#include "aes.c"

#define SERVER_PORT 10000   // 服务器端口
#define QUEUE_SIZE    10        // 连接数
#define BUFFER_SIZE 1024    // 缓冲区

typedef struct aes_arg
{
    int sockfd;
    // mp_int aes_key;
    unsigned char aes_iv[32];
    unsigned char aes_tag[16];
    unsigned char aes_key[32];
} aes_arg;

// 生成长度为num的随机字符串
void generate_rand_str(unsigned char *str, int num)
{
    int i = 0;
    for (i = 0; i < num; i++)
    {
        str[i] = (char) rand() % 256;
    }
}

// 找原根
void find_primitive_root(mp_int *p, mp_int *primitive_root)
{
    // 原根检测
    // 对于数p,求出p-1所有不同的质因子p1,p2…pm
    // 对于任何2<=a<=x-1,判定a是否为p的原根,只需要检验a^((x-1)/p1),a^((x-1)/p2) …a^((x-1)/pm)这m个数
    // 是否存在一个数mod x为1
    // 若存在,a不是x的原根,a否则就是x的原根
    // LTM_PRIME_SAFE保证(p-1)/2也是素数,即p-1只有两个质因子2和(p-1)/2

    // p1=2
    mp_int p1;
    mp_init(&p1);
    mp_init_set(&p1, 2);

    // p2=(p-1)/2
    mp_int p2;
    mp_init(&p2);
    mp_sub_d(p, 1, &p2);
    mp_div_2(&p2, &p2);

    mp_int temp;
    mp_init(&temp);
    // 寻找原根
    // a^((p-1)/2) mod p ?= 1
    // a^2 mod p ?= 1
    while (1)
    {
        mp_exptmod(primitive_root, &p1, p, &temp);    // temp = p_r^2 mod p
        if (mp_cmp_d(&temp, 1) != MP_EQ)
        {
            // 如果上面的结果不是1
            // 再计算 temp = p_r^((p-1)/2) mod p
            mp_exptmod(primitive_root, &p2, p, &temp);
            if (mp_cmp_d(&temp, 1) != MP_EQ)
            {
                // 如果这个结果也不是1则找到原根了
                break;
            }
        }
        mp_add_d(primitive_root, 1, primitive_root);    // +1继续
    }
    mp_clear_multi(&p1, &p2, &temp, NULL);    // 释放
}

// 生成素数p、找到本原根
void generate_p(int sockfd, mp_int *p, mp_int *primitive_root)
{
    srand(time(NULL));
    mp_prime_rand(p, 10, 256, LTM_PRIME_SAFE);    // 生成256位的大素数p,回测10次,LTM_PRIME_SAFE保证(p-1)/2也是素数
    char buffer[BUFFER_SIZE];
    mp_toradix(p, buffer, 10);    // 计算p以r为基的表示法并把数位存在数组str中并以字符串形式输出到屏幕上
    // printf("\n素数: %s\n", buffer);
    send(sockfd, buffer, strlen(buffer) + 1, 0);    // p发过去
    //
    find_primitive_root(p, primitive_root);
    mp_toradix(primitive_root, buffer, 10);
    // printf("\n原根: %s\n", buffer);
    send(sockfd, buffer, strlen(buffer) + 1, 0);    // 原根g发过去
}

// 生成客户端密钥
void generate_client_key(int sockfd, unsigned char *aes_key)
{
    /*-------------------------------------*/
    // 生成p、g、b、y并发送p、g、y
    mp_int p;    // p
    mp_init(&p);    // 初始化mp_int结构使之可以安全的被库中其他函数使用
    mp_int primitive_root;    // 原根
    mp_init(&primitive_root);
    mp_set(&primitive_root, 2);
    generate_p(sockfd, &p, &primitive_root);    // 生成素数p、找到原根g并发送给客户端

    mp_int b;    // 客户端的私钥b
    mp_init(&b);
    mp_rand(&b, p.used);
    mp_int y;    // 客户端的公钥y
    mp_init(&y);
    mp_exptmod(&primitive_root, &b, &p, &y);    // y=g^b mod p

    char buffer[BUFFER_SIZE];
    mp_toradix(&y, buffer, 10);
    send(sockfd, buffer, strlen(buffer) + 1, 0);    // 发送y

    /*-----------------------------------*/
    // 接收服务器的x,key=x^b mod p
    recv(sockfd, buffer, BUFFER_SIZE, 0);
    mp_int x;
    mp_init(&x);
    mp_read_radix(&x, buffer, 10);
    mp_int key;
    mp_init(&key);
    mp_exptmod(&x, &b, &p, &key);
    mp_toradix(&key, buffer, 16);
    // printf("\nkey: \n%s\n", buffer);
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

// void recv_message(aes_arg *arg)
// {
//     int sock = arg->sockfd;
//     struct sockaddr_in client_addr = arg->client_addr;
//     char recv_buffer[512] = {0};
//     int recv_n = 0;
//     // 接收数据
//     while (1)
//     {
//         recv_n = recv(sock, recv_buffer, 512, 0);
//         if (recv_n < 0)    // 接收出错
//         {
//             printf("客户端 %s:%d 接收消息错误\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
//             perror("error: ");
//             close(arg->sockfd);
//             return;
//         }
//         else if (recv_n == 0)    //连接关闭
//         {
//             printf("客户端 %s:%d 连接关闭\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
//             close(arg->sockfd);
//             return;
//         }

//         // printf("recv_n: %d\n", recv_n);
//         recv_buffer[recv_n] = '\0';
//         unsigned int iv_len = 32;
//         unsigned int tag_len = 16;
//         // unsigned int ct_len=recv_n-iv_len;
//         unsigned int ct_len = recv_n - iv_len - tag_len;
//         unsigned char plain_text[256] = {0};
//         // unsigned char cipher_text[256+tag_len]={0};
//         unsigned char cipher_text[256] = {0};
//         unsigned char tag[16] = {0};
//         unsigned char iv[32] = {0};

//         memcpy(iv, recv_buffer, iv_len);
//         memcpy(cipher_text, recv_buffer + iv_len, ct_len);
//         memcpy(tag, recv_buffer + recv_n - tag_len, tag_len);
//         cipher_text[ct_len] = '\0';
//         printf("\n来自客户端 %s:%d的消息:\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
//         BIO_dump_fp(stdout, recv_buffer, recv_n);
//         printf("\niv:\n");
//         BIO_dump_fp(stdout, iv, iv_len);
//         printf("\ntag:\n");
//         BIO_dump_fp(stdout, tag, tag_len);
//         printf("\ncipher_text:\n");
//         BIO_dump_fp(stdout, cipher_text, ct_len);
//         printf("\nkey:\n");
//         BIO_dump_fp(stdout, arg->aes_key, 32);
//         decrypt(arg->aes_key, plain_text, ct_len, cipher_text, iv, iv_len, tag, tag_len);
//         printf("\nplain_text:\n");
//         BIO_dump_fp(stdout, plain_text, ct_len);
//     }
// }

int send_message(aes_arg *arg)
{
    unsigned char plain_text[256] = {0};
    unsigned char cipher_text[256 + 16] = {0};
    unsigned char send_buffer[512] = {0};
    unsigned char tag[16] = {0};
    printf("\n");
    scanf("%s", plain_text);
    // fgets(plain_text, 255, stdin);
    if (strcmp(plain_text, "quit") == 0)
    {
        return 1;
    }
    unsigned int pt_len = strlen(plain_text);
    unsigned int iv_len = 32;
    unsigned int tag_len = 16;
    encrypt(arg->aes_key, plain_text, pt_len, cipher_text, arg->aes_iv, iv_len, tag, tag_len);
    memcpy(cipher_text + pt_len, tag, tag_len);

    printf("\nplain_text: \n");
    BIO_dump_fp(stdout, plain_text, pt_len);
    printf("\ntag: \n");
    BIO_dump_fp(stdout, tag, tag_len);
    printf("\ncipher_text: \n");
    BIO_dump_fp(stdout, cipher_text, pt_len + tag_len);

    // [iv][ct|tag]
    memcpy(send_buffer, arg->aes_iv, iv_len);
    memcpy(send_buffer + iv_len, cipher_text, pt_len + tag_len);
    send_buffer[iv_len + pt_len + tag_len] = '\0';
    printf("\nsendbuffer:\n");
    BIO_dump_fp(stdout, send_buffer, iv_len + pt_len + tag_len);
    printf("\n----------------------------------------------\n");

    if (send(arg->sockfd, send_buffer, strlen(send_buffer), 0) == -1)
    {
        perror("Error ");
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("请输入正确的命令行参数 命令格式： ./client [SERVER_IP_ADDRESS] [CLIENT_IP_ADDRESS]\n");
        exit(-1);
    }

    int sockfd=0;
    // 创建TCP套接字
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Error ");
        exit(-1);
    }
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));    // 初始化
    client_addr.sin_addr.s_addr = inet_addr(argv[2]);    // IP地址(命令行的第三个参数)
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = 0;	// 任意端口
    // 绑定	这里客户端之所以要绑定IP是因为放在了一台机器里模拟
    // kali里添加了多张网卡 为了后面中间人攻击区别 所以客户端也绑定一下
    if (bind(sockfd, (struct sockaddr *) &client_addr, sizeof(client_addr)) < 0)
    {
        perror("Error ");
        close(sockfd);
        exit(-1);
    }
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(SERVER_PORT);

    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("Error ");
        close(sockfd);
        exit(-1);
    }

    // key
    unsigned char *aes_key = (unsigned char *) malloc(sizeof(unsigned char) * 32);
    // 生成iv(32字节)
    unsigned char *aes_iv = (unsigned char *) malloc(sizeof(unsigned char) * 32);
    generate_rand_str(aes_iv, 32);
    // tag(tag)
    unsigned char *aes_tag = (unsigned char *) malloc(sizeof(unsigned char) * 16);
    // generate_rand_str(aes_tag, 16);
    memset(aes_tag, '\0', 16);
    // key(256-bit)
    // mp_int aes_key;
    // mp_init(&aes_key);

    unsigned char buf[512];
    generate_client_key(sockfd, aes_key);    // 生成key
    printf("\n密钥:\n");
    // mp_toradix(&aes_key,buf,16);
    BIO_dump_fp(stdout, aes_key, 32);    // 输出32字节的密钥
    printf("\n初始向量:\n");
    BIO_dump_fp(stdout, aes_iv, 32);
    // printf("\n附加验证数据:\n");
    // BIO_dump_fp(stdout, aes_tag, 16);
    // 发送iv和tag
    send(sockfd, aes_iv, 32, 0);
    send(sockfd, aes_tag, 16, 0);

    aes_arg arg;
    arg.sockfd = sockfd;
    // mp_init_copy(&arg.aes_key, &aes_key);
    memcpy(arg.aes_key, aes_key, 32);
    memcpy(arg.aes_iv, aes_iv, 32);
    memcpy(arg.aes_tag, aes_tag, 16);

    while (1)
    {
        int ret = send_message(&arg);
        if (ret == 1)
            break;
        else if (ret == -1)
        {
            close(sockfd);
            exit(-1);
        }
        // recv_message(&arg);
    }
    close(sockfd);
    return 0;
}



