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
#include <sys/time.h>

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

static void quic_sort(uint32_t *arr, int low, int high)
{
    int i, j, temp;

    for (i = 0; i < high; i++) {
        for (j = 0; j < high - i; j++) {
            if (arr[j] > arr[j+1]) {
                temp = arr[j];
                arr[j] = arr[j+1];
                arr[j+1] = temp;
            }
        }
    }
}

int main(int argc, char **argv)
{	
    int sockfd, count;
    if (argc != 3) {
		printf("parameter error!\n");
		exit(0);
	}
    uint32_t sum_time = 0;
    uint32_t max_time = 0;
    uint32_t temp = 0;
    uint32_t arr[10000];
    struct timeval begin, end;
    sockfd = tcp_socket(argv);
    char buf[2048] = "hello world!";
    char rbuf[2048];
    while (count < 10000) {
        gettimeofday(&begin, NULL);
        send(sockfd, buf, strlen(buf)+1, 0);
        recv(sockfd, rbuf, sizeof(rbuf)-1, 0);
        gettimeofday(&end, NULL);
        temp = end.tv_sec*1000000 - begin.tv_sec*1000000 +end.tv_usec - begin.tv_usec;
        arr[count] = temp;
        sum_time += temp;
        if (max_time < temp)
            max_time = temp;
        count ++;
    }
    quic_sort(arr, 0, 9999);

    printf("max delay = %u, avg delay = %u\n", max_time, sum_time*1.0/10000);
    printf("99.9 delay = %u\n", arr[999]);

	return 0;
}
