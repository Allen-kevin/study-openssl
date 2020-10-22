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


int tcp_socket(char **argv)
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
        return 1; 
    }
    printf("address created\n");
    if (connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }
    printf("Server connected\n");


    return sockfd;
}



int main(int argc, char **argv)
{	
    int sockfd;
    if (argc != 3) {
		printf("parameter error!\n");
		exit(0);
	}

    sockfd = tcp_socket(argv);
    char buf[2048] = "hello world!";
    send(sockfd, buf, strlen(buf)+1, 0);

	return 0;
}
