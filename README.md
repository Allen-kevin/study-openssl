# study-openssl

这个仓库中的代码要做的事有两件，一是为学习openssl而写的小程序，二是为测试
组内一款全栈优先级的用户态协议栈中TLS支持的功能正确性，性能测试采用单独的
工具测试。

## Table of Contents

- [Background](#background)
- [bio-crypto-test](#bio-crypto-test)
- [bio-handshake-test](#bio-handshake-test)
- [evp-test](#evp-test)
- [endecrypt-performance-test](#endecrypt-performance-test)
- [openssl-test](#openssl-test)
- [socket-test](#socket-test)
- [Contributors](#contributors)

## Background

还是忍不住吐槽下，openssl的代码写的真的很难看，也许是我智商不够，
或者C没学好。

重点对openssl中的bio，evp，状态机看了看，所以写的示例程序也是关
于这方面的。握手可以通过SSL完成，也可以通过BIO完成，其实SSL还是
调用了BIO。加解密也可以通过SSL完成，如SSL_read()，SSL_write()，
也可以通过EVP进行。

下面就分别对每个目录下的代码的作用进行介绍。

## bio-crypto-test
使用SSL_read()，SSL_write()进行读写，其实也完成了加密和解密的工作，
但是BIO_read()，BIO_write()也可以做类似的工作，这个目录下就是使用
BIO进行加密和解密的例子程序。
gcc ssl-client.c -o client -lssl -lcrypto -g

gcc ssl-server.c -o server -lssl -lcrypto -g

./server port 1 IP cacert.pem privkey.pem

./client IP port

## bio-handshake-test
TLS/SSL握手在openssl中，通过在服务端调用SSL_accpet()和在客户端调用
SSL_connect()来完成。但是也可以结合使用BIO来进行TLS/SSL握手。这个
例子主要是想说明BIO_new_bio_pair()的使用，因为我们不希望数据包走
TCP/IP发送出去，所以我们使用BIO将数据包取出来使用自定义的接口发出去。
gcc ssl-client.c -o client -lssl -lcrypto -g

gcc ssl-server.c -o server -lssl -lcrypto -g

./server port 1 IP cacert.pem privkey.pem

./client IP port

## evp-test
简单的EVP加解密程序例子。

## endecrypt-perfromance-test
这个是为了配合青云TLS支持的加解密速度测试而写的，只是重复进行ping-pong。
完成TLS/SSL握手后，支持指定消息长度。
gcc client.c -o client -lssl -lcrypto -g

gcc server.c -o server -lssl -lcrypto -g

./server port 1 IP cacert.pem privkey.pem

./client IP port length

## openssl-test
使用SSL完成握手和加解密示例程序。
gcc ssl-client.c -o client -lssl -lcrypto -g

gcc ssl-server.c -o server -lssl -lcrypto -g

./server port 1 IP cacert.pem privkey.pem

./client IP port

## socket-test
简单的TCP/IP套接字使用示例。

## Contributors
wanwenkai@ict.ac.cn
