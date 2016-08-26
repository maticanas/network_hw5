#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "pcap.h"

#include <stdio.h>
#include <winsock2.h>
#include <conio.h>



#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "ws2_32.lib" )

#define MAXBUF  0xFFFF
#define MAXFILTERLEN 100
#define ETEHR_HEADER_LEN 14
#define MAXURL_LEN 1000
#define MAXMALSITENUM 100000 
#define INJECTMAXLEN 10000
#define TCP_DAT_BUF 65536


//#pragma pack(n) 구조체에서 메모리 할당을 n바이트 단위로 하게 된다. 즉, 패딩이 없어진다. 자세한 건 http://kihanyu.tistory.com/entry/%EA%B5%AC%EC%A1%B0%EC%B2%B4Struct-%EB%A9%94%EB%AA%A8%EB%A6%AC-%ED%95%A0%EB%8B%B9-%EA%B7%9C%EC%B9%99 참조


#define FILTER_RULE "host 165.246.12.215 and port 7778" //이거 안 쓴다.

typedef unsigned char u_char;
typedef short SHORT;

enum protocol {
	ipv4, ipv6, tcp
};

unsigned int protocol_number[] = { 0x0800, 0x86DD, 0x06 }; //not right

char * protocol_string[] = { "ipv4", "ipv6", "tcp" };

unsigned int offset = 0;



struct ether_addr
{
	unsigned char ether_addr_octet[6];
};

struct ether_header
{
	struct  ether_addr ether_dhost;
	struct  ether_addr ether_shost;
	unsigned short ether_type;
};

struct ip_header
{
	unsigned char ip_header_len : 4;
	unsigned char ip_version : 4;
	unsigned char ip_tos;
	unsigned short ip_total_length;
	unsigned short ip_id;
	unsigned char ip_frag_offset : 5;
	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;
	unsigned char ip_frag_offset1;
	unsigned char ip_ttl;
	unsigned char ip_protocol;
	unsigned short ip_checksum;
	struct in_addr ip_srcaddr;
	struct in_addr ip_destaddr;
};

struct tcp_header
{
	unsigned short source_port;
	unsigned short dest_port;
	unsigned int sequence;
	unsigned int acknowledge;
	unsigned char ns : 1;
	unsigned char reserved_part1 : 3;
	unsigned char data_offset : 4;
	unsigned char fin : 1;
	unsigned char syn : 1;
	unsigned char rst : 1;
	unsigned char psh : 1;
	unsigned char ack : 1;
	unsigned char urg : 1;
	unsigned char ecn : 1;
	unsigned char cwr : 1;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
};



//for checksum
struct pseudo_header {
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
};
/*
unsigned short in_checksum(unsigned short *ptr,int nbytes) {
register long sum;
unsigned short oddbyte;
register short answer;

sum=0;
while(nbytes>1) {
sum+=*ptr++;
nbytes-=2;
}
if(nbytes==1) {
oddbyte=0;
*((u_char*)&oddbyte)=*(u_char*)ptr;
sum+=oddbyte;
}

sum = (sum>>16)+(sum & 0xffff);
sum = sum + (sum>>16);
answer=(SHORT)~sum;

return(answer);
}
*/
/*
unsigned short checksum(unsigned char * packet)
{
	struct ip_header *ih;
	struct pseudo_header  *psh;
	struct tcp_header *th;
	unsigned short tcpchecksum;
	unsigned char *seudo;
	unsigned int tcp_data_size;

	ih = (struct ip_header *)(packet + 14);
	th = (struct tcp_header *)(((unsigned char *)ih) + (ih->ip_header_len * 4));
	psh->source_address = ih->ip_srcaddr;
	psh->dest_address = 
	pheader.daddr.s_addr = ipheader->daddr;
	pheader.protocol = ipheader->protocol;
	pheader.length = htons(sizeof(struct tcphdr));


	tcp_data_size = sizeof(struct pseudo_header) + sizeof(struct tcp_header);
	seudo = (unsigned char *)malloc(tcp_data_size);
	memcpy(seudo, psh, sizeof(struct pseudo_header));
	memcpy(seudo + sizeof(struct pseudo_header), th, sizeof(struct tcp_header));

	th->checksum = in_checksum((unsigned short*)seudo, tcp_data_size);
}
*/

struct pseudohdr
{
	struct in_addr saddr;
	struct in_addr daddr;
	unsigned char zero;
	unsigned char protocol;
	unsigned short length;
	struct tcp_header tcpheader;
	unsigned char tcp_data[TCP_DAT_BUF] = {0, }; //맞나?
};

unsigned short checksum(unsigned short *buf, int len)
{
	register unsigned long sum = 0;

	while (len--)
		sum += *buf++;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (unsigned short)(~sum);
}

unsigned short calc_ip_checksum(u_char * packet)
{
	struct ip_header *ih;
	ih = (struct ip_header *)(packet + ETEHR_HEADER_LEN);
	return checksum((unsigned short *)ih, (ih->ip_header_len*4) / sizeof(unsigned short));
}

unsigned short calc_checksum(u_char * packet)
{
	struct ip_header *ih;
	struct tcp_header *th;
	struct pseudohdr * pheader;
	unsigned short tcplen;
	unsigned short tcpdatalen;
	unsigned short tcpdataoffset;

	pheader = (struct pseudohdr *)malloc(sizeof(pseudohdr));
	ih = (struct ip_header *)(packet + ETEHR_HEADER_LEN);
	th = (struct tcp_header *)(((unsigned char *)ih) + (ih->ip_header_len * 4));

	tcplen = htons(ih->ip_total_length) - (ih->ip_header_len * 4);
	tcpdatalen = tcplen - (th->data_offset * 4);
	tcpdataoffset = ETEHR_HEADER_LEN + (ih->ip_header_len * 4) + (th->data_offset * 4);

	pheader->saddr = ih->ip_srcaddr;
	pheader->daddr = ih->ip_destaddr;
	pheader->protocol = ih->ip_protocol;
	pheader->length = htons(tcplen);
	pheader->zero = 0;
	//memcpy(pheader->tcpheader, th, sizeof(struct tcp_header));
	memcpy(pheader->tcp_data, packet + tcpdataoffset, tcpdatalen);
	memcpy(&(pheader->tcpheader), th, sizeof(th));

	printf("tcpdataoffset = %d\n", tcpdataoffset);
	printf("tcpdatalen = %d\n", tcpdatalen);
	printf("tcplen = %d\n", tcplen);
	printf("data_offset %d \n", th->data_offset);

	// calculate TCP checksum
	return checksum((unsigned short *)pheader, (sizeof(struct pseudohdr)) / sizeof(unsigned short));
}




void print_ether_header(const unsigned char *data);
int print_ip_header(const unsigned char *data);
int print_tcp_header(const unsigned char *data);
void print_data(const unsigned char *data);
int filter_ipv4(const unsigned char *pkt_data);
int filter_tcp(const unsigned char *pkt_data);

struct malsite
{
	char url[MAXURL_LEN];
	//unsigned long long Hash;
};

int get_mal_site(struct malsite * ms, FILE *fp)
{
	int msnum = 0;
	char BOM;
	fscanf(fp, "%c", &BOM);
	fscanf(fp, "%c", &BOM);
	fscanf(fp, "%c", &BOM);

	printf("automatically removed BOM ef bb bf\nif there is no BOM, you should change get_mal_site() code\n");


	while (!feof(fp))
	{
		fscanf(fp, "%s\n", ms[msnum].url);
		//printf("%s\n", ms[msnum].url);
		msnum++;
	}
	return msnum;
}

bool filter_mal_site(char HTTP_url[MAXURL_LEN], struct malsite * ms, int msnum)
{
	int idx;
	for (idx = 0; idx < msnum; idx++)
	{
		if (strstr(ms[idx].url, HTTP_url))
		{
			printf("malsite blocked : %s\n", HTTP_url);
			return true;
		}
	}
	return false;
}

bool ipv4filter_L4(struct ip_header *ih, protocol p)
{
	if (protocol_number[p] != ih->ip_protocol)
	{
		//printf("not %s\n", protocol_string[p]);
		return 0;
	}
	return 1;
}

bool filter_L3(struct ether_header *eh, protocol p)
{
	unsigned short ether_type = ntohs(eh->ether_type);
	//eh->ether_type = ether_type;
	if (ether_type != protocol_number[p])
	{
		//printf("%x", ether_type);
		//printf("not %s protocol   ", protocol_string[p]);
		return 0;
	}
	return 1;
}

bool filter_tcp(unsigned char packet[MAXBUF], struct tcp_header ** th)
{
	struct ether_header *eh;
	struct ip_header *ih;
	eh = (struct ether_header *)packet;
	if (filter_L3(eh, ipv4))
	{
	ih = (struct ip_header *)(packet + ETEHR_HEADER_LEN);
	//ih = (struct ip_header *)(packet);
	if (ipv4filter_L4(ih, tcp))
	{
		//printf("it's tcp packet\n");
		*th = (struct tcp_header *)(((unsigned char *)ih) + (ih->ip_header_len * 4));
		return 1;
	}
	}
	return 0;
}

bool filter_http(unsigned char packet[MAXBUF], struct malsite *ms, int msnum)
{
	struct tcp_header * th;
	unsigned char * http_header;
	unsigned char * HTTP_loc;
	unsigned char * HTTP_end_loc;
	unsigned char * HTTP_url_loc;
	unsigned char * HTTP_url_end_loc;
	char HTTP_url[MAXURL_LEN] = { 0, };
	int url_len = 0;

	if (!filter_tcp(packet, &th))
	{
		//printf("not tcp");
		return 0;
	}
	http_header = (unsigned char *)th + (th->data_offset * 4);
	HTTP_loc = (unsigned char *)strstr((const char *)http_header, "HTTP/1.1");
	if (HTTP_loc == NULL)
		HTTP_loc = (unsigned char *)strstr((const char *)http_header, "HTTP/1.0");

	if (HTTP_loc == NULL)
	{
		//printf("not http\n");
		return false;
	}
	//printf("http packet =>");

	HTTP_end_loc = (unsigned char *)strstr((const char *)http_header, "\n\n");
	HTTP_url_loc = (unsigned char *)strstr((const char *)http_header, "Host: ") + 6;

	if (HTTP_url_loc == (unsigned char *)6)
	{
		//printf("cannot find url\n");
		return false;
	}

	HTTP_url_end_loc = (unsigned char *)strstr((const char *)HTTP_url_loc, "\n") - 1; //1 0d 0a에서 0a의 위치를 주기 때문에 1 뺌 
	url_len = (int)((int)HTTP_url_end_loc - (int)HTTP_url_loc);
	memcpy((char *)HTTP_url, (char *)HTTP_url_loc, url_len);
	HTTP_url[url_len] = '\0';

	printf("url : %s\n", HTTP_url);

	if (filter_mal_site(HTTP_url, ms, msnum))
		return true;
	else
		return false;
}



int main() {
	FILE *fp_malsite;
	//unsigned char packet[MAXBUF];

	fp_malsite = fopen("mal_site.txt", "r");

	struct malsite * ms;
	int msnum;

	ms = (struct malsite *)malloc(sizeof(malsite)*MAXMALSITENUM);
	msnum = get_mal_site(ms, fp_malsite);


	pcap_if_t *alldevs = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];



	int offset = 0;

	// find all network adapters
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		printf("dev find failed\n");
		return -1;
	}
	if (alldevs == NULL) {
		printf("no devs found\n");
		Sleep(1000);
		//return -1;
	}
	// print them
	pcap_if_t *d; int i;
	for (d = alldevs, i = 0; d != NULL; d = d->next) {
		printf("%d-th dev: %s ", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	int inum;

	printf("enter the interface number: ");
	scanf("%d", &inum);
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++); // jump to the i-th dev

															  // open
	pcap_t  *fp;
	if ((fp = pcap_open_live(d->name,      // name of the device
		65536,                   // capture size
		1,  // promiscuous mode
		20,                    // read timeout
		errbuf
		)) == NULL) {
		printf("pcap open failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("pcap open successful\n");
	

	pcap_freealldevs(alldevs); // we don't need this anymore

	struct pcap_pkthdr *header;

	const unsigned char *pkt_data;
	const unsigned char *tmp;
	unsigned char * packet;
	u_char packet_inject[INJECTMAXLEN];
	int res;

	struct ip_header *ih;
	struct tcp_header *th;
	struct pseudohdr pheader;
	unsigned short tcplen;
	unsigned short tcp_datalen;
	unsigned short len_before_tcp_data;
	unsigned short totlen;
	unsigned short iplen;
	const char * text = "you cannot connect";


	printf("before print\n");

	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		if (res == 0) continue;

		packet = (unsigned char *)pkt_data;
		if (filter_http(packet, ms, msnum))
		{

			ih = (struct ip_header *)(packet + ETEHR_HEADER_LEN);
			th = (struct tcp_header *)(((unsigned char *)ih) + (ih->ip_header_len * 4));

			//tcp_data 이전까지 모두 복사하려고 준비
			tcplen = ih->ip_total_length - (ih->ip_header_len * 4);
			tcp_datalen = ih->ip_total_length - (ih->ip_header_len * 4) - (th->data_offset * 4);
			len_before_tcp_data = ETEHR_HEADER_LEN + (ih->ip_header_len * 4) + (th->data_offset * 4);
			iplen = (ih->ip_header_len * 4) + (th->data_offset * 4) + 19;

			printf("mychecksum : %hu\n", calc_checksum(packet));
			printf("realchecksum : %hu\n", th->checksum);
			

			//fin flag setting
			th->fin = 1;

			//여기 tcp data 추가
			//////tcp data
			//th->data_offset = ; //여기 해 줘야
			ih->ip_total_length = htons(iplen);
			ih->ip_checksum = 0;
			ih->ip_checksum = calc_ip_checksum(packet);
			
			memcpy(packet + len_before_tcp_data, text, 19);

			//여기 seq ack 이거 처리해 줘야 한다
			th->sequence = htonl(ntohl(th->sequence) + tcp_datalen );
			
			//

			//checksum 처리
			th->checksum = 0;
			th->checksum = calc_checksum(packet);

			//total length
			totlen = len_before_tcp_data + 19;

			//http inject packet
			memcpy(packet_inject, packet, totlen);

			if (pcap_sendpacket(fp, packet_inject, totlen/* size */) != 0)
			{
				fprintf(stderr, "\nError sending the packet: %s \n", pcap_geterr(fp));
				return -1;
			}
		}
		
	}

	Sleep(1);

	return 0;

}

void print_ether_header(const unsigned char *data)
{
	struct  ether_header *eh;               // 이더넷 헤더 구조체
	unsigned short ether_type;
	eh = (struct ether_header *)data;       // 받아온 로우 데이터를 이더넷 헤더구조체 형태로 사용
	ether_type = ntohs(eh->ether_type);       // 숫자는 네트워크 바이트 순서에서 호스트 바이트 순서로 바꿔야함

	if (ether_type != 0x0800)
	{
		printf("ether type wrong\n");
		return;
	}
	// 이더넷 헤더 출력
	printf("\n============ETHERNET HEADER==========\n");
	printf("Dst MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for dest
		eh->ether_dhost.ether_addr_octet[0],
		eh->ether_dhost.ether_addr_octet[1],
		eh->ether_dhost.ether_addr_octet[2],
		eh->ether_dhost.ether_addr_octet[3],
		eh->ether_dhost.ether_addr_octet[4],
		eh->ether_dhost.ether_addr_octet[5]);
	printf("Src MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for src
		eh->ether_shost.ether_addr_octet[0],
		eh->ether_shost.ether_addr_octet[1],
		eh->ether_shost.ether_addr_octet[2],
		eh->ether_shost.ether_addr_octet[3],
		eh->ether_shost.ether_addr_octet[4],
		eh->ether_shost.ether_addr_octet[5]);
}

int print_ip_header(const unsigned char *data)
{
	struct  ip_header *ih;
	ih = (struct ip_header *)data;  // 마찬가지로 ip_header의 구조체 형태로 변환

	printf("\n============IP HEADER============\n");
	printf("IPv%d ver \n", ih->ip_version);
	// Total packet length (Headers + data)
	//printf("Packet Length : %d\n", ntohs(ih->ip_total_length) + 14);
	//printf("TTL : %d\n", ih->ip_ttl);
	if (ih->ip_protocol == 0x06)
	{
		printf("Protocol : TCP\n");
	}
	printf("Src IP Addr : %s\n", inet_ntoa(ih->ip_srcaddr));
	printf("Dst IP Addr : %s\n", inet_ntoa(ih->ip_destaddr));

	// return to ip header size
	return ih->ip_header_len * 4;
}

int print_tcp_header(const unsigned char *data)
{
	struct  tcp_header *th;
	th = (struct tcp_header *)data;

	printf("\n============TCP HEADER============\n");
	printf("Src Port Num : %d\n", ntohs(th->source_port));
	printf("Dest Port Num : %d\n", ntohs(th->dest_port));
	/*
	printf("Flag :");
	if (ntohs(th->cwr))
	{
	printf(" CWR ");
	}
	if (ntohs(th->ecn))
	{
	printf(" ENC ");
	}
	if (ntohs(th->urg))
	{
	printf(" URG ");
	}
	if (ntohs(th->ack))
	{
	printf(" ACK ");
	}
	if (ntohs(th->psh))
	{
	printf(" PUSH ");
	}
	if (ntohs(th->rst))
	{
	printf(" RST ");
	}
	if (ntohs(th->syn))
	{
	printf(" SYN ");
	}
	if (ntohs(th->fin))
	{
	printf(" FIN ");
	}
	*/
	printf("\n");

	// return to tcp header size
	return th->data_offset * 4;
}

void print_data(const unsigned char *data)
{
	printf("\n============DATA============\n");
	printf("%s\n", data);
}

int filter_ipv4(const unsigned char *pkt_data)
{
	struct  ether_header *eh;               // 이더넷 헤더 구조체
	unsigned short ether_type;
	eh = (struct ether_header *)pkt_data;       // 받아온 로우 데이터를 이더넷 헤더구조체 형태로 사용
	ether_type = ntohs(eh->ether_type);

	if (ether_type != 0x0800)
	{
		printf("not ipv4 packet\n");
		return 1;
	}
	return 0;
}

int filter_tcp(const unsigned char *pkt_data)
{
	pkt_data = pkt_data + 14;
	struct  ip_header *ih;
	ih = (struct ip_header *)pkt_data;
	if (ih->ip_protocol != 0x06)
	{
		printf("protocol : %x\n", ih->ip_protocol);
		printf("not tcp protocol\n");
		return 1;
	}
	return 0;
}