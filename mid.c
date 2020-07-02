/*
* @Author: Sun
* @Date:   2020-06-29 14:46:55
* @Last Modified by:   Sun
* @Last Modified time: 2020-07-02 21:02:37
*/
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

typedef struct m_arg
{
    int server_sock;    // 服务器套接字
    int client_sock;    // 客户端套接字
    u_char iv[12];    // 初始向量
    u_char aad[16];    // 附加验证数据
    u_char server_key;    // 服务器密钥
    u_char client_key;    // 客户端密钥
} m_arg;

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("输入参数个数错误\n");
        return ARGERROR;
    }
    char *server_ip = argv[1];    // 接收输入参数

    int s_socket = socket(AF_INET, SOCK_STREAM, 0);    //创建TCP套接字
    if (s_socket < 0)
    {
        printf("创建TCP套接字失败\n");
        return SOCKETERROR;
    }
    struct sockaddr_in server_addr;    // 服务器地址结构体
    unsigned int port = 10000;    // 监听端口
    bzero(&server_addr, sizeof(server_addr));    // 初始化
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);    // 网络字节序
    server_addr.sin_addr.s_addr = htonl(INADDRANY);    // 本机IP都行
    // 绑定IP和端口
    if (bind(s_socket, (struct sockaddr *) &server_addr, sizeof(server_addr)))
    {
        printf("socket绑定失败\n");
        close(s_socket);
        retur BINDERROR;
    }
    printf("服务器绑定至%s\n", inet_ntoa(server_addr.sin_addr));
    // 监听
    if (listen(s_socket, 10))
    {
        printf("监听失败\n");
        close(s_socket);
        return LISTENERROR;
    }
    printf("服务器启动，等待客户端连接...\n");
    int c_socket;
    while (1)
    {
        char client_ip[INET_ADDRSTRLEN] = "";    // netinet/in.h中的宏定义，定义32位IPv4的地址使用10进制+句点表示时所占用的char数组的长度
        struct sockaddr_in client_addr;    // 保存客户端addr
        socklen_t client_addr_len = sizeof(client_addr);
        c_socket = accept(s_socket, (struct sockaddr *) &client_addr, &client_addr_len);    // 获取连接
        if (c_socket < 0)
        {
            printf("获取连接错误\n");
            continue;
        }
        printf("客户端");
        printf("%s", inet_ntoa(client_addr.sin_addr));
        printf("连接成功\n");


    }
}
