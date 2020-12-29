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
#include <openssl/err.h>

#define MAXBUF 1024

int tcp_socket(char **argv)
{
    int sockfd;
    struct sockaddr_in my_addr;
    unsigned int myport, lisnum;

	if (argv[1])
		myport = atoi(argv[1]);
	else
		myport = 7838;

    printf("begin bind!\n");
	if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(1);
	} else {
		printf("socket created\n");
	}

	bzero(&my_addr, sizeof(my_addr));
	my_addr.sin_family = PF_INET;
	my_addr.sin_port = htons(myport);
	if (argv[2])
		my_addr.sin_addr.s_addr = inet_addr(argv[2]);
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
    
    return sockfd;
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
    
    printf("server get from client port: %d, new fd = %d\n", their_addr.sin_port, new_fd);
    char buf[4096];
    int recv_len = 0;
    int slen = 0;
    while (1) { 
        recv_len = recv(new_fd, buf, sizeof(buf)-1, 0);
        if (recv_len <= 0) {
            printf("receive failure, close session!\n");
            close(new_fd);
        } else {
            printf("msg: %s\n", buf);
        }
        slen = send(new_fd, buf, recv_len, 0);
    }
}


int main(int argc, char **argv)
{
    int sockfd;
    sockfd = tcp_socket(argv);

    recv_send_data(sockfd);

	return 0;
}
