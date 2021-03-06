/* server */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
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
#include <openssl/symhacks.h>
#define MAXBUF 4096
#define BUFSIZE 4096

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


void recv_send_data(int sockfd)
{
    int new_fd;
	socklen_t len;
    struct sockaddr_in their_addr;

	len = sizeof(struct sockaddr);
	if ((new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &len))
		== -1) {
		perror("accept");
		exit(errno);
	} else {
		printf("server: got connection from %s, port %d, socket %d\n",
		inet_ntoa(their_addr.sin_addr),
		ntohs(their_addr.sin_port), new_fd);
	}
    
    char buf[4096];
    int recv_len = 0;
    recv_len = recv(new_fd, buf, sizeof(buf)-1, 0);
    if (recv_len <= 0) {
        printf("receive failure, close session!\n");
        close(new_fd);
        return;
    }

}

void tls_ssl_init(SSL_CTX *ctx, char **argv)
{
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(SSLv23_server_method());

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

void tls_init()
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}


int main(int argc, char **argv)
{
	char buffer[MAXBUF+1];
    int new_fd, ret = 1, len;

	SSL_CTX *ctx;
    SSL *ssl;

    tls_init();

	ctx = SSL_CTX_new(SSLv23_server_method());

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
    //tls_ssl_init(ctx, argv);

    EVP_CIPHER_CTX *evp_ctx;
    BIO *server = NULL, *server_io = NULL;

    if (!BIO_new_bio_pair(&server, BUFSIZE, &server_io, BUFSIZE)) {
        ERR_print_errors_fp(stdout);
        goto err;
    }

    ssl = SSL_new(ctx);
    SSL_set_bio(ssl, server, server);
    //ssl->version;

    new_fd = tcp_socket(argv);
    len = recv(new_fd, buffer, sizeof(buffer)-1, 0);
    printf("rcv client hello msg: %s, len = %d\n", buffer, strlen(buffer));
    BIO_write(server_io, buffer, len);
    ret = SSL_accept(ssl);
    
    char *bio_buf = NULL;
    len = BIO_ctrl_pending(server_io);
    printf("server len = %d\n", len);
    bio_buf = (char *)OPENSSL_malloc(len);
    len = BIO_read(server_io, bio_buf, len);
    printf("bio buf: %s\n", bio_buf);
    
    send(new_fd, bio_buf, len, 0);//send server hello

    memset(buffer, 0, MAXBUF+1);
    len = recv(new_fd, buffer, sizeof(buffer)-1, 0);
    printf("client cipher msg: %s, len = %d\n", buffer, strlen(buffer));
    BIO_write(server_io, buffer, len);
    ret = SSL_do_handshake(ssl);

    char out[1024], in[1024];
   // EVP_DecryptUpdate(evp_ctx, out, &len, buffer, 100);
   // printf("decrypt msg: %s, len = %d\n", out, strlen(out));
   //
 /* test send data */
    memset(buffer, 0, MAXBUF);
    strcpy(buffer, "hello world");
    SSL_write(ssl, buffer, strlen(buffer));
    len = 0;
    len = BIO_ctrl_pending(server_io);
    printf("encrypt len = %d\n", len);
    BIO_read(server_io, out, len);
    printf("encrypt msg = %s\n", out);
    send(new_fd, out, len, 0);//send encrypt data

    /* test recv data */
    memset(buffer, 0, MAXBUF);
    len = recv(new_fd, buffer, sizeof(buffer)-1, 0);
    printf("not decrypt msg = %s\n", buffer);
    len = BIO_write(server_io, buffer, len);
    memset(buffer, 0, MAXBUF);
    SSL_read(ssl, buffer, len);
    printf("decrypt msg = %s\n", buffer);
   /*
    const char *cipher_name = SSL_get_cipher_name(ssl);
    printf("cipher name: %s\n", cipher_name);
    const char *cipher_version = SSL_get_cipher_version(ssl);
    printf("cipher version: %s\n", cipher_version);

    EVP_CIPHER *evp_cipher = NULL;
    SSL_SESSION *ssl_session = NULL;
    SSL_CIPHER *ssl_cipher = NULL;

    ssl_session = SSL_get_session(ssl);
    ssl_cipher = SSL_get_current_cipher(ssl);
    ssl_cipher_get_evp_cipher(ctx, ssl_cipher, &evp_cipher);
*/
err:
    SSL_shutdown(ssl);
    SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}
