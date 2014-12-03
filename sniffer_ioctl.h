#ifndef __SNIFFER_IOCTL_
#define __SNIFFER_IOCTL__

struct sniffer_flow_entry {
	unsigned mode;
	uint32_t src_ip;
	uint32_t dest_ip;
	uint16_t src_port;
	uint16_t dest_port;
	int action;
	char * dev_file;
};

#define SNIFFER_IOC_MAGIC       'p'

#define SNIFFER_FLOW_ENABLE     _IOW(SNIFFER_IOC_MAGIC, 0x1, struct sniffer_flow_entry)
#define SNIFFER_FLOW_DISABLE    _IOW(SNIFFER_IOC_MAGIC, 0x2, struct sniffer_flow_entry)

#define SNIFFER_IOC_MAXNR   0x3


#define SNIFFER_ACTION_NULL     0x0
#define SNIFFER_ACTION_CAPTURE  0x1
#define SNIFFER_ACTION_DPI      0x2

#define ETH_HEADER_SIZE 14
#define IP_HEADER_SIZE 20
#define TCP_HEADER_SIZE 20

typedef struct {
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint16_t ethertype;
}ethernet_hdr_t;

struct ip_hdr_t{
	uint8_t version_ihl;
	uint8_t dscp_ecn;
	uint16_t total_len;
	uint16_t identification;
	uint16_t flags;
	uint8_t ttl;
	uint8_t protocol;
	
	uint16_t checksum;
	uint32_t src_ip;
	uint32_t dst_ip;
	uint8_t options_and_data[0];
};
#define IP_HL(ip)	(((ip)->version_ihl) & 0x0f)

struct tcp_hdr_t{
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq;
	uint32_t ack_num;
	uint8_t offset;
	uint8_t flag;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_ACK  0x10
	uint16_t win;
	uint16_t checksum;
	uint16_t urg;
	uint8_t options_and_data[0];
};


#endif /* __SNIFFER_IOCTL__ */
