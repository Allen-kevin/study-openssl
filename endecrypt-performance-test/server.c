/* server */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/comp.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/async.h>
#include <openssl/symhacks.h>
#include <openssl/ct.h>

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define MAXBUF 1500

#define TLS_HANDSHAKE_INIT 1
#define TLS_HANDSHAKE_WAITING 2
#define TLS_HANDSHAKE_END 3
uint32_t de_sum_time = 0;
uint32_t de_sum_length = 0;
uint32_t en_sum_time = 0;
uint32_t en_sum_length = 0;

struct tls_bio {
    int state;
    int fd;
    void (*tls_handshake)(int fd, SSL *ssl, BIO *sink);
    SSL *ssl;
    BIO *source;
    BIO *sink;
    char *buffer;
};

int tcp_socket(char **argv)
{
    int sockfd, new_fd;
    socklen_t len;
    struct sockaddr_in my_addr, their_addr;
    unsigned int myport, lisnum;

	if (argv[1])
		myport = atoi(argv[1]);
	else
		myport = 7838;

	if (argv[2])
		lisnum = atoi(argv[2]);
	else
		lisnum = 2;

	if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(1);
	} else {
		printf("socket created\n");
	}

	bzero(&my_addr, sizeof(my_addr));
	my_addr.sin_family = PF_INET;
	my_addr.sin_port = htons(myport);
	if (argv[3])
		my_addr.sin_addr.s_addr = inet_addr(argv[3]);
	else
		my_addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr))
		== -1) {
		perror("bind");		
		exit(1);
	} else
		printf("binded\n");

	if (listen(sockfd, lisnum) == -1) {
		perror("listen");
		exit(1);
	} else
		printf("begin listen\n");

    len = sizeof(struct sockaddr);
    new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &len); 
    if (new_fd == -1) {
        perror("accept");
        exit(errno);
    } else {
        printf("server: got connection from %s, port %d, socket %d\n", inet_ntoa(their_addr.sin_addr),
        ntohs(their_addr.sin_port), new_fd);
    }
   
    return new_fd;
}


void tls_ssl_init(SSL_CTX *ctx, char **argv)
{
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	if (SSL_CTX_use_certificate_file(ctx, argv[4], SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, argv[5], SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}
}


static int decrypt(struct tls_bio *tls, int len)
{

    len = BIO_write(tls->sink, tls->buffer, len);
    if (unlikely(len <= 0)) {
        printf("BIO write failure!\n");
        return len;
    }
    memset(tls->buffer, 0, len);

    return SSL_read(tls->ssl, tls->buffer, len);
}

static int tls_rcv(struct tls_bio *tls)
{
    int len = 0, rlen = 0;
    struct timeval begin, end;

    memset(tls->buffer, 0, MAXBUF);
    len = recv(tls->fd, tls->buffer, MAXBUF, 0);

    gettimeofday(&begin, NULL);//testing
    rlen = decrypt(tls, len);
    gettimeofday(&end, NULL);//testing
    de_sum_length += len;
    de_sum_time += end.tv_sec*1000000 - begin.tv_sec*1000000 + end.tv_usec - begin.tv_usec;

    return rlen;
}


static int encrypt(struct tls_bio *tls, int len)
{
    SSL_write(tls->ssl, tls->buffer, len);
    len = BIO_ctrl_pending(tls->sink);

    if (unlikely(len <= 0)) {
        printf("ssl write failure!\n");
        exit(-1);
    }
    return BIO_read(tls->sink, tls->buffer, len);
}


static int tls_send(struct tls_bio *tls, int len)
{
    struct timeval begin, end;
    int wlen = 0;

    gettimeofday(&begin, NULL);//testing
    wlen = encrypt(tls, len);
    gettimeofday(&end, NULL);//testing
    en_sum_time += end.tv_sec*1000000 - begin.tv_sec*1000000 + end.tv_usec - begin.tv_usec;
    en_sum_length += len;
    
    return send(tls->fd, tls->buffer, wlen, 0);//send server change cipher
}

static void tls_handshake(int fd, SSL *ssl, BIO *server_io)
{
	char buffer[MAXBUF+1];
    int len = 0, ret = 0;
    len = recv(fd, buffer, sizeof(buffer)-1, 0);
    printf("client hello msg: %s, len = %d\n", buffer, strlen(buffer));
    BIO_write(server_io, buffer, len);
    ret = SSL_accept(ssl);
    
    char *bio_buf = NULL;
    len = BIO_ctrl_pending(server_io);
    printf("server len = %d\n", len);
    bio_buf = (char *)OPENSSL_malloc(len);
    len = BIO_read(server_io, bio_buf, len);
    printf("bio buf: %s\n", bio_buf);
    
    send(fd, bio_buf, len, 0);//send server hello

}


static void tls_bio_init(struct tls_bio *tls, SSL *ssl, BIO *server, BIO *server_io, void (*tls_handshake)())
{
    tls->state = TLS_HANDSHAKE_INIT;
    tls->tls_handshake = tls_handshake;
    tls->source = server;
    tls->sink = server_io;
    tls->ssl = ssl;
    tls->buffer = (char *)malloc(MAXBUF);
}


static int tls_handshake_complete(struct tls_bio *tls)
{
    while (tls->state != TLS_HANDSHAKE_END) {
        if (tls->state == TLS_HANDSHAKE_INIT) {
            tls->tls_handshake(tls->fd, tls->ssl, tls->sink);
            tls->state = TLS_HANDSHAKE_WAITING;
        } else if (tls->state == TLS_HANDSHAKE_WAITING) {
            tls->tls_handshake(tls->fd, tls->ssl, tls->sink);
            tls->state = TLS_HANDSHAKE_END;
        } 
    }

    return 0;
}



static void tls_app_rcv_send(struct tls_bio *tls)
{
    int len;
    int count = 0;
       
    while (count < 1000) {
        len = tls_rcv(tls);
        len = tls_send(tls, len);
        count ++;
    }
    printf("decrypt sum time = %lld, sum length = %lld, rate = %lf Mbit/s\n", de_sum_time, de_sum_length, de_sum_length*1.0*8*1000*1000/(de_sum_time*1024*1024));
    printf("encrypt sum time = %lld, sum length = %lld, rate = %lf Mbit/s\n", en_sum_time, en_sum_length, en_sum_length*1.0*8*1000*1000/(en_sum_time*1024*1024));
}


static void tls_get_cipher_info(struct tls_bio *tls)
{
    const char *cipher_name;
    const char *cipher_version;

    cipher_name = SSL_get_cipher_name(tls->ssl);
    cipher_version = SSL_get_cipher_version(tls->ssl);

    printf("cipher name: %s\n", cipher_name);
    printf("cipher version: %s\n", cipher_version);

}

int main(int argc, char **argv)
{
	SSL_CTX *ctx;
    SSL *ssl;
    struct tls_bio tls_bio_test;

    tls_bio_test.fd = tcp_socket(argv);
	ctx = SSL_CTX_new(SSLv23_server_method());
    tls_ssl_init(ctx, argv);
    ssl = SSL_new(ctx);

    BIO *server = NULL, *server_io = NULL;

    if (!BIO_new_bio_pair(&server, MAXBUF, &server_io, MAXBUF)) {
        ERR_print_errors_fp(stdout);
        goto err;
    }

    SSL_set_bio(ssl, server, server);

    tls_bio_init(&tls_bio_test, ssl, server, server_io, tls_handshake);
    tls_handshake_complete(&tls_bio_test);
    
    tls_get_cipher_info(&tls_bio_test);

    tls_app_rcv_send(&tls_bio_test);

err:
    SSL_shutdown(ssl);
    SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}
