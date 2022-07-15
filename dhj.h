#ifndef _DHJ_H
#define _DHJ_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>
#include <net/route.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <net/if.h>       /* ifreq struct */
#include <netdb.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>

#define ROUTE_ADD 1
#define ROUTE_DEL 2

#define null_char(x, n)  char *x = NULL;
#define heap_char(x, n)  char *x = calloc(n, 1)
#define stack_char(x, n) char x[n] = {0}
#define safe_free(x) if(x) {free(x);} x = NULL

#define LOG_FILE "/var/log/dhj.log"

static inline void sleep_us(int time);
static inline void sleep_us(int time) {
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = time;
	select(0, NULL, NULL, NULL, &tv);
}

static inline void sleep_ms(int time);
static inline void sleep_ms(int time) {
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = time * 1000;
	select(0, NULL, NULL, NULL, &tv);
}


static inline void sleep_s(int time);
static inline void sleep_s(int time) {
	struct timeval tv;
	tv.tv_sec = time;
	tv.tv_usec = rand() % 100;
	select(0, NULL, NULL, NULL, &tv);
}

static inline void logff(const char *file, const char *function, int line, const char *format, ...);
static inline void logff(const char *file, const char *function, int line, const char *format, ...) {
	va_list ap;
	char message[4096] = {0};

	va_start(ap, format);
	int len = vsnprintf(message, sizeof(message), format, ap);
	message[sizeof(message) - 1] = 0;
	va_end(ap);

	if(len > 0 && (size_t)len < sizeof(message) - 1 && message[len - 1] == '\n') {
		message[len - 1] = 0;
	}

	FILE *fp = fopen(LOG_FILE, "a");
	if(!fp) {
		return;
	}

	time_t t = time(NULL);
	char timestr[4096] = {0};
	strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&t));
	fprintf(fp, "[%s] %s:%s [%d] %s\n", timestr, file, function, line, message);
	fclose(fp);
}

static inline void logdd(const char *file, const char *function, int line, const char *format, ...);
static inline void logdd(const char *file, const char *function, int line, const char *format, ...) {
	va_list ap;
	char message[4096] = {0};

	va_start(ap, format);
	int len = vsnprintf(message, sizeof(message), format, ap);
	message[sizeof(message) - 1] = 0;
	va_end(ap);

	if(len > 0 && (size_t)len < sizeof(message) - 1 && message[len - 1] == '\n') {
		message[len - 1] = 0;
	}

	time_t t = time(NULL);
	char timestr[4096] = {0};
	strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&t));
	fprintf(stderr, "[%s] %s:%s [%d] %s\n", timestr, file, function, line, message);
}

#define FFL __FILE__, __FUNCTION__, __LINE__
#define logf(...)  logff(__FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define logd(...)  logdd(__FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)

static inline double timeval_difference(struct timeval *t1, struct timeval *t2);
static inline double timeval_difference(struct timeval *t1, struct timeval *t2) {
	return ((double) (((t2->tv_sec - t1->tv_sec) * 1.0) + ((t2->tv_usec - t1->tv_usec) / 1000000.0)));
}

static inline bool xxstrstr(const char *s1, const char *s2, const char s);
static inline bool xxstrstr(const char *s1, const char *s2, const char s) {
	char *p = (char *)s2;
	char *q = strstr((char *)s1, p);

	if(!q) {
		return false;
	}

	if((q == s1 && strlen(p) == strlen(q)) ||                      // p(AB) -> s1(AB)
	(q == s1 && *(q + strlen(p)) == s) ||                          // p(AB) -> s1(AB\n...\nCD,EF)
	(*(q - 1) == s && q + strlen(p) == (s1 + strlen(s1))) ||       // p(AB) -> s1(CD\nEF\n...\nAB)
	(*(q - 1) == s && *(q + strlen(p)) == s)) {                    // p(AB) -> s1(CD\n...\nAB\n...n\EF)
		return true;
	}

	return false;
}

static inline bool xstrstr(const char *s1, const char *s2);
static inline bool xstrstr(const char *s1, const char *s2) {
	char *p = (char *)s2;
	char *q = strstr((char *)s1, p);

	if(!q) {
		return false;
	}

	if((q == s1 && strlen(p) == strlen(q)) ||                        // p(AB) -> s1(AB)
	(q == s1 && *(q + strlen(p)) == ',') ||                          // p(AB) -> s1(AB,...,CD,EF)
	(*(q - 1) == ',' && q + strlen(p) == (s1 + strlen(s1))) ||       // p(AB) -> s1(CD,EF,...,AB)
	(*(q - 1) == ',' && *(q + strlen(p)) == ',')) {                  // p(AB) -> s1(CD,...,AB,...,EF)
		return true;
	}

	return false;
}

static inline int time_ms(void);
static inline int time_ms(void) {
        struct timeval time;

        if(!gettimeofday(&time, NULL)) {
	       return (time.tv_sec % 1000) * 1000 + time.tv_usec / 1000;
	}

	return -1;
}

static inline void *xnstrdup(void *data, size_t n);
static inline void *xnstrdup(void *data, size_t n) {
	char *p = calloc(n, sizeof(char *));

	if(!p) {
		return NULL;
	}

	memcpy(p, data, n);

	return p;
}

static inline void *xrealloc(void *p, size_t n);
static inline void *xrealloc(void *p, size_t n) {
	p = realloc(p, n);

	if(!p) {
		abort();
	}

	return p;
}

#ifdef _WIN32
	#define get_pointer_useable_size(x) _msize(x)
#else
	#define get_pointer_useable_size(x) malloc_usable_size(x)
#endif

static inline void *xnstrcat(void *p, void *data, size_t n);
static inline void *xnstrcat(void *p, void *data, size_t n) {
	size_t len = strlen((char *)p);
	size_t need = len - get_pointer_useable_size(p) + n + 1;

	if(len + n + 1 > get_pointer_useable_size(p)) {
		p = realloc(p, len + n + 1);
	}

	if(!p) {
		abort();
	}

	memcpy(p + len, data, n);

	return p;
}

static inline void *xstrdup(void *data);
static inline void *xstrdup(void *data) {
	char *str = (char *)data;
	char *p;
	int len = 0;

	if(p = strchr(str, '\n')) {
		len = p - str;
	} else {
		len = strlen(str);
	}

	if(p) p = NULL;

	if(!(p = calloc(len + 1, 1))) {
		return NULL;
	}

	memcpy(p, str, len);
	return p;
}

/* printf_hex:  huangjue.deng  2020.3.18
 *	while let data to get struct,
 *	s_t *s = malloc(sizeof(*s));
 * 	printf_hex(s, sizeof(s_t));
 *
 */
static inline bool printf_hex(void *data, size_t len);
static inline bool printf_hex(void *data, size_t len) {
	uint8_t buf[len + 1];
	memcpy(buf, data, len);
	for(int i = 0; i < len; i++) {
		fprintf(stdout, "%02x", buf[i]);

		(i + 1) % 16 ? ((i + 1) % 4 ? : fprintf(stdout, " ")) : fprintf(stdout, "\n");
	}

	fprintf(stdout, "\n");
	return true;
}

static inline uint8_t *to_upper(uint8_t *data);
static inline uint8_t *to_upper(uint8_t *data) {
	int len = strlen(data);

	int i = 1;
	do {
		if((data)[i] >= 'a' && (data)[i] <= 'z') {
			(data)[i] -= 0x20;
		}
	} while(++i < len);

	return data;
}

/* get_hex:  huangjue.deng  2020.3.18
 *	while let data to get struct,
 * 	s_t *s = malloc(sizeof(*s));
 * 	printf_hex(s, sizeof(s_t));
 *
 */
static inline uint8_t *get_heX(void *data, size_t len);
static inline uint8_t *get_heX(void *data, size_t len) {
	uint8_t buf[len];
	uint8_t *ret = calloc(len * 2 + 1, 1);

	memcpy(buf, data, len);
	for(int i = 0; i < len; i++) {
		sprintf(&ret[i * 2], "%02X", buf[i]);
	}

	return ret;
}


/* get_hex:  huangjue.deng  2020.3.18
 *	while let data to get struct,
 * 	s_t *s = malloc(sizeof(*s));
 * 	printf_hex(s, sizeof(s_t));
 *
 */
static inline uint8_t *get_hex(void *data, size_t len);
static inline uint8_t *get_hex(void *data, size_t len) {
	uint8_t buf[len];
	uint8_t *ret = calloc(len * 2 + 1, 1);

	memcpy(buf, data, len);
	for(int i = 0; i < len; i++) {
		sprintf(&ret[i * 2], "%02x", buf[i]);
	}

	return ret;
}

/* get_hex_back:  huangjue.deng  2020.3.18
 *	while let data to get struct,
 * 	s_t *s = malloc(sizeof(*s));
 * 	printf_hex(s, sizeof(s_t));
 *
 */
static inline uint8_t *get_hex_back(void *data, size_t len);
static inline uint8_t *get_hex_back(void *data, size_t len) {
	uint8_t buf[len];
	uint8_t *ret = calloc(len / 2 + 1, 1);

	memcpy(buf, data, len);
	to_upper(buf);

	for(int i = 0; i < len / 2; i++) {
		ret[i] = (buf[i * 2] >= 'A'? (buf[i * 2] - 'A' + 0xA) : (buf[i * 2] - '0')) * 0x10 + (buf[i * 2 + 1] >= 'A'? (buf[i * 2 + 1] - 'A' + 0xA) : (buf[i * 2 + 1] - '0'));
		//logd("        [%02x %02x]: ([%02x] * 0x10)[%02x] + [%02x] = [%02x]:[%c]", buf[i * 2], buf[i * 2 + 1], buf[i * 2] >= 'A'? (buf[i * 2] - 'A' + 0xA) : (buf[i * 2] - '0'), (buf[i * 2] >= 'A'? (buf[i * 2] - 'A' + 0xA) : (buf[i * 2] - '0')) * 0x10, buf[i * 2 + 1] >= 'A'? (buf[i * 2 + 1] - 'A' + 0xA) : (buf[i * 2 + 1] - '0'), ret[i]);
	}

	return ret;
}

/* get_format_hex:  huangjue.deng  2020.3.18
 *	while let data to get struct,
 * 	s_t *s = malloc(sizeof(*s));
 * 	printf_hex(s, sizeof(s_t));
 *
 */
static inline uint8_t *get_format_hex(void *data, size_t len);
static inline uint8_t *get_format_hex(void *data, size_t len) {
	uint8_t buf[len + 1];
	uint8_t *ret = malloc(len * 2 + len / 4 + 1);
	memcpy(buf, (char *) data, len);
	memset(ret, 0, sizeof(ret));
	int count = 0;
	int j = 0;
	for(int i = 0; i < len; i++) {
		j = i * 2 + count;
		sprintf(&ret[j], "%02x", buf[i]);

		(i + 1) % 16 ? ((i + 1) % 4 ? : (sprintf(&ret[j + 2], " ") && count++)) : (sprintf(&ret[j + 2], "\n") && count++);
	}

	return ret;
}


#ifdef _WIN32
static inline int windows_control_route(int action, const char *ip, const char *mask, const char *gateway);
static inline int windows_control_route(int action, const char *ip, const char *mask, const char *gateway) {
	NET_LUID luid;
	NET_IFINDEX idx;

	wchar_t *walias;
	int len = MultiByteToWideChar( CP_ACP ,0,iface ,strlen( iface), NULL, 0);
	walias = (wchar_t *)malloc(len * sizeof(wchar_t));
	MultiByteToWideChar(CP_ACP, 0, iface, strlen(iface), walias, len);
	walias[len]= '\0' ;

	ConvertInterfaceAliasToLuid(walias, &luid);
	ConvertInterfaceLuidToIndex(&luid, &idx);

	MIB_IPFORWARDROW  row = { 0 };
	row.dwForwardDest = inet_addr(ip); //目标网络
	row.dwForwardMask = inet_addr(mask); //掩码
	row.dwForwardProto = MIB_IPPROTO_NETMGMT;
	row.dwForwardType = MIB_IPROUTE_TYPE_DIRECT;
	row.dwForwardMetric1 = 311; //route print 里的Metric
	row.dwForwardIfIndex = idx; //网卡索引,用arp -a,route print可以查看本机网卡的索引
	row.dwForwardNextHop = inet_addr(gateway); //网关

	DWORD dwRet;
	if(action == ROUTE_ADD) {
		dwRet = CreateIpForwardEntry(&row);
	} else {
		dwRet = DeleteIpForwardEntry(&row);
	}

	free(walias);
	return dwRet;
}
#endif

#ifdef __linux__
/*
 *  IPv4 add/del route item in route table
    refer to https://www.cnblogs.com/wangshide/archive/2012/10/25/2740410.html
 */
static inline bool io_control_route(int action, char *ip, char *mask, char *iface, char *gw);
static inline bool io_control_route(int action, char *ip, char *mask, char *iface, char *gw) {
	struct rtentry route;  /* route item struct */
	char target[128] = {0};
	char gateway[128] = {0};
	char netmask[128] = {0};

	struct sockaddr_in *addr;

	int skfd;

	/* clear route struct by 0 */
	memset((char *)&route, 0x00, sizeof(route));

	/* default target is net (host)*/
	route.rt_flags = RTF_UP ;

	if(ip) {   // default is a network target
		strcpy(target, ip);
		addr = (struct sockaddr_in*) &route.rt_dst;
		addr->sin_family = AF_INET;
		addr->sin_addr.s_addr = inet_addr(target);

	}
 
	if(mask) {   // netmask setting
		strcpy(netmask, mask);
		addr = (struct sockaddr_in*) &route.rt_genmask;
		addr->sin_family = AF_INET;
		addr->sin_addr.s_addr = inet_addr(netmask);

	}

	if(gw) {
		strcpy(gateway, gw);
		addr = (struct sockaddr_in*) &route.rt_gateway;
		addr->sin_family = AF_INET;
		addr->sin_addr.s_addr = inet_addr(gateway);
		route.rt_flags |= RTF_GATEWAY;
	}

	if(iface) {  /* device setting */
		route.rt_dev = iface;
	}

/*
	if(mtu) {  //mtu setting
		route.rt_flags |= RTF_MTU;
		route.rt_mtu = atoi(*args);
	}
*/

	/* create a socket */
	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(skfd < 0) {
		perror("socket");
		return false;
	}

	/* tell the kernel to accept this route */
	if(action == ROUTE_DEL) {  /* del a route item */
		if(ioctl(skfd, SIOCDELRT, &route) < 0) {
			perror("SIOCDELRT");
			close(skfd);
			return false;
		}

	} else if(action == ROUTE_ADD) {  /* add a route item */
		if(ioctl(skfd, SIOCADDRT, &route) < 0) {
			perror("SIOCADDRT");
			close(skfd);
			return false;
		}

	} else {
		return false;
	}

	close(skfd);
	return true;
}

/*
* following functions are ipv6 address transfrom
* (from string to address struct and so on.)
* these functions from net-tools inet6.c file.
*/

int INET6_resolve(char *name, struct sockaddr_in6 *sin6) {

	struct addrinfo req, *ai;
	int s;

	memset (&req, '\0', sizeof req);
	req.ai_family = AF_INET6;
	if((s = getaddrinfo(name, NULL, &req, &ai)))  {
		return -1;
	}

	memcpy(sin6, ai->ai_addr, sizeof(struct sockaddr_in6));

	freeaddrinfo(ai);

	return 0;
}

int INET6_getsock(char *bufp, struct sockaddr *sap) {
	struct sockaddr_in6 *sin6;

	sin6 = (struct sockaddr_in6 *) sap;
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = 0;

	if(inet_pton(AF_INET6, bufp, sin6->sin6_addr.s6_addr) <= 0) {
		return -1;
	}

	return 16;
}

int INET6_input(int type, char *bufp, struct sockaddr *sap) {
	switch (type)  {
		case 1:
			return (INET6_getsock(bufp, sap));
		default:
			return (INET6_resolve(bufp, (struct sockaddr_in6 *) sap));
	}
}


/* IPv6 add/del route item in route table */
/* main part of this function is from net-tools inet6_sr.c file */
static inline bool io_control_route6(int action, char *ipv6, char *mask, char *iface, char *gw);
static inline bool io_control_route6(int action, char *ipv6, char *mask, char *iface, char *gw) {
	struct in6_rtmsg rt;          /* ipv6 route struct */
	struct ifreq ifr;             /* interface request struct */
	struct sockaddr_in6 sa6;      /* ipv6 socket address */
	char target[128];
	//char gateway[128] = "NONE";
	int prefix_len;               /* network prefix length */
	char *devname = NULL;         /* device name */
	char *cp;
	int mtu = 0;

	int skfd = -1;

	strcpy(target, ipv6);

	if(!strcmp(target, "default")) {
		prefix_len = 0;
		memset(&sa6, 0, sizeof(sa6));
	} else {
		if ((cp = strchr(target, '/'))) {
			prefix_len = atol(cp + 1);
			sprintf(cp, "1");
			*cp = '\0';
			if(prefix_len < 0 || prefix_len > 128) {
				return false;
			}

		} else {
			prefix_len = 128;
		}

		if(INET6_input(1, target, (struct sockaddr *) &sa6) < 0 && INET6_input(0, target, (struct sockaddr *) &sa6) < 0) {
			return false;
		}
	}

	/* Clean out the RTREQ structure. */
	memset((char *) &rt, 0, sizeof(struct in6_rtmsg));

	memcpy(&rt.rtmsg_dst, sa6.sin6_addr.s6_addr, sizeof(struct in6_addr));

	/* Fill in the other fields. */
	rt.rtmsg_flags = RTF_UP;
	if (prefix_len == 128) {
		rt.rtmsg_flags |= RTF_HOST;
	}

	rt.rtmsg_metric = 1;
	rt.rtmsg_dst_len = prefix_len;

/*
	if(gw) {
		if(rt.rtmsg_flags & RTF_GATEWAY) {
			return fasle;
		}

		strcpy(gateway, gw);

		if(INET6_input(1, gateway, (struct sockaddr *) &sa6) < 0) {
			return false;
		}

		memcpy(&rt.rtmsg_gateway, sa6.sin6_addr.s6_addr, sizeof(struct in6_addr));
		rt.rtmsg_flags |= RTF_GATEWAY;
	}

	if(mod) {
		rt.rtmsg_flags |= RTF_MODIFIED;
	}

	if(MTU)  {
		mtu = MTU;
	}
*/

	if(iface) {
		devname = iface;
	}

	/* Create a socket to the INET6 kernel. */
	if((skfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		return false;
	}

	memset(&ifr, 0, sizeof(ifr));

	if(action == ROUTE_ADD) {
		if(devname) {/* device setting */
			strcpy(ifr.ifr_name, devname);

			if(ioctl(skfd, SIOGIFINDEX, &ifr) < 0) {
				perror("SIOGIFINDEX");
				return false;
			}

			rt.rtmsg_ifindex = ifr.ifr_ifindex;
		}

		if(mtu) {/* mtu setting */
			ifr.ifr_mtu = mtu;

			if (ioctl(skfd, SIOCSIFMTU, &ifr) < 0) {
				perror("SIOCGIFMTU");
				return false;
			}
		}

		if(ioctl(skfd, SIOCADDRT, &rt) < 0) {
			perror("SIOCADDRT");
			close(skfd);
			return false;
		}

	}

	/* Tell the kernel to accept this route. */
	if(action == ROUTE_DEL) {
		if(ioctl(skfd, SIOCDELRT, &rt) < 0) {
			perror("SIOCDELRT");
			close(skfd);
			return false;
		}

	}

	/* Close the socket. */
	close(skfd);
	return true;
}
#endif

static inline char *time_str(void);
static inline char *time_str(void) {
	time_t t = time(NULL);
	char timestr[4096] = {0};
	strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&t));
	return xstrdup(timestr);
}

static inline char *time_ms_str(void);
static inline char *time_ms_str(void) {
	time_t t = time(NULL);
	char timestr[4096] = {0};
	strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&t));
	struct timeval t_;
	gettimeofday(&t_, NULL);
	sprintf(timestr + strlen(timestr), ".%03ld", t_.tv_usec / 1000);
	return (char *)xstrdup(timestr);
}


#ifndef timeradd
#define timeradd(a, b, r) do {\
		(r)->tv_sec = (a)->tv_sec + (b)->tv_sec;\
		(r)->tv_usec = (a)->tv_usec + (b)->tv_usec;\
		if((r)->tv_usec >= 1000000)\
			(r)->tv_sec++, (r)->tv_usec -= 1000000;\
	} while (0)
#endif

#ifndef timersub
#define timersub(a, b, r) do {\
		(r)->tv_sec = (a)->tv_sec - (b)->tv_sec;\
		(r)->tv_usec = (a)->tv_usec - (b)->tv_usec;\
		if((r)->tv_usec < 0)\
			(r)->tv_sec--, (r)->tv_usec += 1000000;\
	} while (0)
#endif


#endif
