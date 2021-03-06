#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAXBUF 1024

void ShowCerts(SSL *ssl)
{
	X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl);
	if (cert != NULL) {
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		free(line);
		X509_free(cert);
	} else {
		printf("No msg about certificate.\n");
	}
}


int tcp_socket_connect(char **argv)
{
    int sockfd;
    struct sockaddr_in dest;

    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(atoi(argv[2]));
    if (inet_aton(argv[1], (struct in_addr *)&dest.sin_addr.s_addr) == 0) {
        perror(argv[1]);
        exit(errno);
    }
    
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket\n");
        return -1;
    }

    printf("address created\n");
    if (connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }
    printf("Server connected\n");

    return sockfd;
}


void tls_init()
{
 	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
}


void tls_connect(SSL_CTX *ctx, SSL *ssl, BIO *client_io)
{
}

int main(int argc, char **argv)
{	
    if (argc != 3) {
		printf("parameter error!\n");
		exit(0);
	}

	char *buffer = NULL, *buffer_cipher = NULL;
	int len, sockfd, ret = 5;
	SSL_CTX *ctx;
	SSL *ssl;

    sockfd = tcp_socket_connect(argv);
    tls_init();

	ctx = SSL_CTX_new(SSLv23_client_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}
    
    BIO *client = NULL, *client_io = NULL;
    size_t bufsiz = 2048;

    if (!BIO_new_bio_pair(&client, bufsiz, &client_io, bufsiz)) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
	
	/* Non-blocking bio. */
	BIO_set_nbio(client, 1);
	BIO_set_nbio(client_io, 1);

	ssl = SSL_new(ctx);
    SSL_set_bio(ssl, client, client);
	SSL_set_connect_state(ssl);
	SSL_do_handshake(ssl);
//    ret = SSL_connect(ssl); //
    ;
    len = BIO_ctrl_pending(client_io);

    if (len <= 0)
        goto err;

    buffer = (char *)OPENSSL_malloc(1024);
	len = BIO_read(client_io, buffer, 1024);
    
    send(sockfd, buffer, len, 0); //send client hello

	printf("client state: %s\n", SSL_state_string_long(ssl));
    //receive server hello
	memset(buffer, 0, 1024);
    len = recv(sockfd, buffer, 1024, 0);
    printf("msg: %s, len = %d\n", buffer, strlen(buffer));
    BIO_write(client_io, buffer, len);
	if (!SSL_is_init_finished(ssl)) {
    	ret = SSL_do_handshake(ssl);

		len = BIO_ctrl_pending(client_io);
		printf("client cipher len = %d\n", len);
		if (len <= 0) {
			goto err;
		}
		buffer_cipher = (char *)OPENSSL_malloc(1024);
		len = BIO_read(client_io, buffer_cipher, len);

		send(sockfd, buffer_cipher, len, 0);//
		printf("what happen!\n");
	}


err:
	printf("client err!\n");
    close(sockfd);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	return 0;
}
