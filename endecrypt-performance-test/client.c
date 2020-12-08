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



static void tls_init()
{
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
}


static int tcp_handshake(int argc, char **argv)
{
	int sockfd;
	struct sockaddr_in dest;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Socket");
		exit(errno);
	}
	printf("socket created\n");

	bzero(&dest, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(atoi(argv[2]));
	if (inet_aton(argv[1], (struct in_addr *)&dest.sin_addr.s_addr) == 0) {
		perror(argv[1]);
		exit(errno);
	}
	printf("address created\n");
	if (connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
		perror("Connect ");
		exit(errno);
	}
	printf("client tcp connnected\n");
	
	return sockfd;
}

int main(int argc, char **argv)
{
	int sockfd, len;
	char buffer[MAXBUF+1];

	SSL_CTX *ctx;
	SSL *ssl;

	if (argc != 4) {
		printf("parameter error!\n");
		exit(0);
	}

	tls_init();
	sockfd = tcp_handshake(argc, argv);

	ctx = SSL_CTX_new(SSLv23_client_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sockfd);
	if (SSL_connect(ssl) == -1)
		ERR_print_errors_fp(stderr);
	
	int count = 0;
	while (count < 1000) {
		bzero(buffer, MAXBUF+1);
		FILE *fd = fopen("text.txt", "r");
		fgets(buffer, atoi(argv[3])+1, fd);

		if (SSL_write(ssl, buffer, strlen(buffer)) <= 0){
			printf("msg %s send failure!\n", buffer);
			goto finish;
		} 

		bzero(buffer, MAXBUF+1);
		if (SSL_read(ssl, buffer, MAXBUF) <= 0){
			printf("rcv msg failure!\n");
			goto finish;
		}
		count++;
		fclose(fd);
	}


finish:
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(sockfd);
	SSL_CTX_free(ctx);
	return 0;
}
