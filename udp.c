#include "/work/dhj.h/dhj.h"
#define BUFFER_SIZE 128

bool flag_s = false;
int sockfd = 0;
struct sockaddr_in servaddr;
socklen_t peerlen = 0;
char buf[1500] = {0};

int main(int argc, char **argv) {
	if(argc != 4) {
		logd("./%s s/c (address) (port)", argv[0]);
		return 1;
	}

	if(!strcasecmp(argv[1], "s")) {
		flag_s = true;

	} else if(strcasecmp(argv[1], "c")) {
		logd("./%s s/c (address) (port)", argv[0]);
		return 1;
	}

	if(!(sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))) {
		logd("socket: %s", strerror(errno));
		return -1;
	}

	logd("Address: %s %s", argv[2], argv[3]);
	logd("sock fd [%d]", sockfd);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(atoi(argv[3]));
	servaddr.sin_addr.s_addr = inet_addr(argv[2]);
	peerlen = sizeof(servaddr);

	if(flag_s) {
		if(bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) {
			logd("bind: %s", strerror(errno));
			return 1;
		}
    
		while(true) {
			if(recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&servaddr, &peerlen) < 0) {
				logd("recvfrom: %s", strerror(errno));
				continue;
			}

			char address[INET_ADDRSTRLEN] = {0};
			int port = ntohs(servaddr.sin_port);
			inet_ntop(AF_INET, &servaddr.sin_addr, address, INET_ADDRSTRLEN);
			logd("Received a message from (%s port %d): %s", address, port, buf);
		}
	} else {
		char address[INET_ADDRSTRLEN] = {0};
		int port = ntohs(servaddr.sin_port);
		inet_ntop(AF_INET, &servaddr.sin_addr, address, INET_ADDRSTRLEN);

		for(int i = 0; i < sizeof(buf); i++) {
			buf[i] = i % 0xff;
		}

		while(true) {
			if(sendto(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&servaddr, peerlen) >= 0) {
				logd("Sent a message to (%s port %d): %s", address, port, buf);
			} else {
				logd("Sent: %s", strerror(errno));
			}
		}
	}

	close(sockfd);
	exit(0);
}
