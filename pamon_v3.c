/* Written from scratch, but kernel-to-user space API usage
* dissected from lolpcap:
*  Copyright 2011, Chetan Loke <loke.chetan@gmail.com>
*  License: GPL, version 2.0
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <time.h>
#include <linux/filter.h>

#include <pthread.h>
#include "hashmap.h"
#include "pkt_parse.h"

#ifndef likely
# define likely(x)          __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
# define unlikely(x)                __builtin_expect(!!(x), 0)
#endif

struct block_desc {
        uint32_t version;
        uint32_t offset_to_priv;
        struct tpacket_hdr_v1 h1;
};

struct ring {
        struct iovec *rd;
        uint8_t *map;
        struct tpacket_req3 req;
};

#pragma pack(1)
typedef enum {
	SYN_SENT = 1,
	SYN_ACK = 2,
}PKT_STATUS;

typedef struct {
	uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
}HASH_NODE_KEY;

typedef struct {
	HASH_NODE_KEY key;
	int64_t       time;
	PKT_STATUS    status;
}HASH_NODE_DATA;
#pragma pack()

int g_dest_port = 0;
static unsigned long packets_total = 0, bytes_total = 0;
static sig_atomic_t sigint = 0;
static long packets_cnts = 0;
static long packets_bytes = 0;
static long packets_time = 0;
static long error_pkts = 0;
static struct hashmap *hash_map = NULL;

#define TIME_1_MS 1000
#define TIME_1_SECOND (1000 * TIME_1_MS)

#ifdef PORT_9930
#define DEST_PORT 9930
#endif

#ifdef PORT_9780
#define DEST_PORT 9780
#endif

static uint64_t total_num = 0;
static uint64_t total_delay_us = 0;
static uint64_t total_max_us = 0;

static uint64_t num_1s = 0;
static uint64_t delay_us_1s = 0;
static uint64_t max_us_1s = 0;

static uint64_t num_5s = 0;
static uint64_t delay_us_5s = 0;
static uint64_t max_us_5s = 0;

static uint64_t num_10s = 0;
static uint64_t delay_us_10s = 0;
static uint64_t max_us_10s = 0;

static uint64_t num_60s = 0;
static uint64_t delay_us_60s = 0;
static uint64_t max_us_60s = 0;

#define MAX_MINUTES_HIT_CNTS  (100*1024)
static int hit_cnts_minutes = 0;
static int delay_arrays_minutes[MAX_MINUTES_HIT_CNTS] = {0};


static void sighandler(int num)
{
        sigint = 1;
}


//tcpdump  tcp -s 64 -nn -dd
//{ 0x28, 0, 0, 0x0000000c },
//{ 0x15, 0, 5, 0x000086dd },
//{ 0x30, 0, 0, 0x00000014 },
//{ 0x15, 6, 0, 0x00000006 },
//{ 0x15, 0, 6, 0x0000002c },
//{ 0x30, 0, 0, 0x00000036 },
//{ 0x15, 3, 4, 0x00000006 },
//{ 0x15, 0, 3, 0x00000800 },
//{ 0x30, 0, 0, 0x00000017 },
//{ 0x15, 0, 1, 0x00000006 },
//{ 0x6, 0, 0, 0x00000040 },
//{ 0x6, 0, 0, 0x00000000 },

//tcpdump  tcp and port 6379 -nn -dd
//{ 0x28, 0, 0, 0x0000000c },
//{ 0x15, 0, 6, 0x000086dd },
//{ 0x30, 0, 0, 0x00000014 },
//{ 0x15, 0, 15, 0x00000006 },
//{ 0x28, 0, 0, 0x00000036 },
//{ 0x15, 12, 0, 0x000018eb },
//{ 0x28, 0, 0, 0x00000038 },
//{ 0x15, 10, 11, 0x000018eb },
//{ 0x15, 0, 10, 0x00000800 },
//{ 0x30, 0, 0, 0x00000017 },
//{ 0x15, 0, 8, 0x00000006 },
//{ 0x28, 0, 0, 0x00000014 },
//{ 0x45, 6, 0, 0x00001fff },
//{ 0xb1, 0, 0, 0x0000000e },
//{ 0x48, 0, 0, 0x0000000e },
//{ 0x15, 2, 0, 0x000018eb },
//{ 0x48, 0, 0, 0x00000010 },
//{ 0x15, 0, 1, 0x000018eb },
//{ 0x6, 0, 0, 0x00040000 },
//{ 0x6, 0, 0, 0x00000000 },
#if 0
static int set_filter(int fd)
{
#ifdef PORT_9930
    struct sock_filter bpf_code[] = {
{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 6, 0x000086dd },
{ 0x30, 0, 0, 0x00000014 },
{ 0x15, 0, 15, 0x00000006 },
{ 0x28, 0, 0, 0x00000036 },
{ 0x15, 12, 0, 0x000026ca },
{ 0x28, 0, 0, 0x00000038 },
{ 0x15, 10, 11, 0x000026ca },
{ 0x15, 0, 10, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 0, 8, 0x00000006 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 6, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x48, 0, 0, 0x0000000e },
{ 0x15, 2, 0, 0x000026ca },
{ 0x48, 0, 0, 0x00000010 },
{ 0x15, 0, 1, 0x000026ca },
{ 0x6, 0, 0, 0x00000040 },
{ 0x6, 0, 0, 0x00000000 }
    };
#endif

//tcpdump tcp and port 9780 -s 64 -nn -dd
#ifdef PORT_9780
	struct sock_filter bpf_code[] = {
{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 6, 0x000086dd },
{ 0x30, 0, 0, 0x00000014 },
{ 0x15, 0, 15, 0x00000006 },
{ 0x28, 0, 0, 0x00000036 },
{ 0x15, 12, 0, 0x00002634 },
{ 0x28, 0, 0, 0x00000038 },
{ 0x15, 10, 11, 0x00002634 },
{ 0x15, 0, 10, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 0, 8, 0x00000006 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 6, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x48, 0, 0, 0x0000000e },
{ 0x15, 2, 0, 0x00002634 },
{ 0x48, 0, 0, 0x00000010 },
{ 0x15, 0, 1, 0x00002634 },
{ 0x6, 0, 0, 0x00000040 },
{ 0x6, 0, 0, 0x00000000 }
	};
#endif

	struct sock_fprog bpf;
	memset(&bpf,0x00,sizeof(bpf));
	bpf.len = sizeof(bpf_code) / sizeof(struct sock_filter);
	bpf.filter = bpf_code;
	int ret = setsockopt(fd,SOL_SOCKET, SO_ATTACH_FILTER, &bpf,sizeof(bpf));
	if (ret < 0)
	{
		printf("setsockopt( *sock_fd, SOL_SOCKET,  SO_ATTACH_FILTER, &bpf, sizeof(bpf) err.\n");
	}

	return ret;
}
#endif 

static int setup_socket(struct ring *ring, char *netdev)
{
        int err, i, fd, v = TPACKET_V3;
        struct sockaddr_ll ll;
        unsigned int blocksiz = 1 << 22, framesiz = 1 << 11;
        unsigned int blocknum = 64;

        fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd < 0) {
                perror("socket");
                exit(1);
        }

        err = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
        if (err < 0) {
                perror("setsockopt");
                exit(1);
        }

        memset(&ring->req, 0, sizeof(ring->req));
        ring->req.tp_block_size = blocksiz;
        ring->req.tp_frame_size = framesiz;
        ring->req.tp_block_nr = blocknum;
        ring->req.tp_frame_nr = (blocksiz * blocknum) / framesiz;
        ring->req.tp_retire_blk_tov = 60;
        ring->req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

        err = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &ring->req,
                        sizeof(ring->req));
        if (err < 0) {
                perror("setsockopt");
                exit(1);
        }

		//err = set_filter(fd);
		//if (err < 0) {
        //        perror("set filter");
        //        exit(1);
        //}
			
        ring->map = mmap(NULL, ring->req.tp_block_size * ring->req.tp_block_nr,
                        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
        if (ring->map == MAP_FAILED) {
                perror("mmap");
                exit(1);
        }

        ring->rd = malloc(ring->req.tp_block_nr * sizeof(*ring->rd));
        assert(ring->rd);
        for (i = 0; i < ring->req.tp_block_nr; ++i) {
                ring->rd[i].iov_base = ring->map + (i * ring->req.tp_block_size);
                ring->rd[i].iov_len = ring->req.tp_block_size;
        }

        memset(&ll, 0, sizeof(ll));
        ll.sll_family = PF_PACKET;
        ll.sll_protocol = htons(ETH_P_ALL);
        ll.sll_ifindex = if_nametoindex(netdev);
        ll.sll_hatype = 0;
        ll.sll_pkttype = 0;
        ll.sll_halen = 0;

        err = bind(fd, (struct sockaddr *) &ll, sizeof(ll));
        if (err < 0) {
                perror("bind");
                exit(1);
        }

        return fd;
}


static void handle_pkt_test(struct tpacket3_hdr *ppd)
{
		PKT_INFO_S pkt_info;
	    pkt_info.peth_pkt = (uint8_t *)((uint8_t *) ppd + ppd->tp_mac);
	    pkt_info.pkt_len = ppd->tp_len;
	    if (PKT_PARSE_OK != pkt_get_hdr(&pkt_info))
	    {  
	    	error_pkts++;
			return;
	    }

		if (pkt_info.proto != PKT_IPPROTO_TCP) {
			return;
		}

		//printf("Handle Pkt...\n");

		//uint64_t cur_time_us = ppd->tp_sec * 1000000 + (ppd->tp_nsec / 1000);
		struct timeval tv;
	    gettimeofday(&tv, NULL);
		uint64_t cur_time_us = (long long)tv.tv_sec * 1000 + (long long)tv.tv_usec / 1000;

		HASH_NODE_KEY key;
		int need_handle = 0;
		int pkt_status = 0;
		uint8_t *l4 = pkt_info.l4;	
		int tcp_flags = ((PKT_TCP_HEADER_S*)(l4))->flags;
		if (TCP_ACKF(l4) && TCP_SYN(l4)) {
			//syn_ack
			if (g_dest_port == pkt_info.sport) {
				key.sip = pkt_info.dip;
				key.sport = pkt_info.dport;
				key.dip = pkt_info.sip;
				key.dport = pkt_info.sport;
				need_handle = 1;
				pkt_status = SYN_ACK;
			}			
		}else if (TCP_SYN(l4) > 0) {
			//syn
			if (pkt_info.dport == g_dest_port) {
				key.sip = pkt_info.sip;
				key.sport = pkt_info.sport;
				key.dip = pkt_info.dip;
				key.dport = pkt_info.dport;
				need_handle = 1;
				pkt_status = SYN_SENT;
			}
		}

		if (need_handle != 1) {
			#ifdef TEST_DEBUG1
			printf("[key]Sip:%d.%d.%d.%d Sport:%u Dip:%d.%d.%d.%d Dport:%u Not Need Handle, Time %lu.\n",
				(pkt_info.sip >> 24) & 0xff, 
				(pkt_info.sip >> 16) & 0xff, 
				(pkt_info.sip >> 8) & 0xff, 
				(pkt_info.sip >> 0) & 0xff, 
				pkt_info.sport,
				(pkt_info.dip >> 24) & 0xff, 
				(pkt_info.dip >> 16) & 0xff, 
				(pkt_info.dip >> 8) & 0xff, 
				(pkt_info.dip >> 0) & 0xff, 
				pkt_info.dport, cur_time_us);
			
			#endif

			return;
		}

		//handle 
		
		HASH_NODE_DATA *data = NULL;
		data = hashmap_get(hash_map, (void *)&key);
		if (data == NULL) {
			//new data
			HASH_NODE_DATA new_data;
			new_data.key.sip = key.sip;
			new_data.key.sport = key.sport;
			new_data.key.dip = key.dip;
			new_data.key.dport = key.dport;
			new_data.time = cur_time_us;

			if (pkt_status == SYN_SENT) {
				new_data.status = SYN_SENT;
			}else if (pkt_status == SYN_ACK) {
				return;
			}
					
			hashmap_set(hash_map, &new_data);
		#ifdef TEST_DEBUG	 
			printf("Hash Cnt: %d.\n", hashmap_count(hash_map));
			printf("[key]Sip:%d.%d.%d.%d Sport:%u Dip:%d.%d.%d.%d Dport:%u New SynSent Time:%lu Seq %d tcp_flags %d tcp_syn %d.\n",
				(pkt_info.sip >> 24) & 0xff, 
				(pkt_info.sip >> 16) & 0xff, 
				(pkt_info.sip >> 8) & 0xff, 
				(pkt_info.sip >> 0) & 0xff, 
				pkt_info.sport,
				(pkt_info.dip >> 24) & 0xff, 
				(pkt_info.dip >> 16) & 0xff, 
				(pkt_info.dip >> 8) & 0xff, 
				(pkt_info.dip >> 0) & 0xff, 
				pkt_info.dport, cur_time_us, TCP_SN(l4), tcp_flags, TCP_SYN(l4));
		#endif	
				
		}else {
			if (pkt_status == SYN_SENT) {
				//update
				data->time = cur_time_us;
				data->status = SYN_SENT;

				printf("[key]Sip:%d.%d.%d.%d Sport:%u Dip:%d.%d.%d.%d Dport:%u Recv SynSent, Update it Time:%lu. \n",
						(pkt_info.sip >> 24) & 0xff, 
						(pkt_info.sip >> 16) & 0xff, 
						(pkt_info.sip >> 8) & 0xff, 
						(pkt_info.sip >> 0) & 0xff, 
						pkt_info.sport,
						(pkt_info.dip >> 24) & 0xff, 
						(pkt_info.dip >> 16) & 0xff, 
						(pkt_info.dip >> 8) & 0xff, 
						(pkt_info.dip >> 0) & 0xff, 
						pkt_info.dport, cur_time_us);
				
				return;
			}else if (pkt_status == SYN_ACK){
				//delete
				hashmap_delete(hash_map, (void *)&key);
				#ifdef TEST_DEBUG	 
					printf("Hash Cnt: %d.\n", hashmap_count(hash_map));
					printf("[key]Sip:%d.%d.%d.%d Sport:%u Dip:%d.%d.%d.%d Dport:%u Recv SynAck, Delete it Time:%lu. \n",
						(pkt_info.sip >> 24) & 0xff, 
						(pkt_info.sip >> 16) & 0xff, 
						(pkt_info.sip >> 8) & 0xff, 
						(pkt_info.sip >> 0) & 0xff, 
						pkt_info.sport,
						(pkt_info.dip >> 24) & 0xff, 
						(pkt_info.dip >> 16) & 0xff, 
						(pkt_info.dip >> 8) & 0xff, 
						(pkt_info.dip >> 0) & 0xff, 
						pkt_info.dport, cur_time_us);
				#endif
			}
		
		}	
}


static void walk_block(struct block_desc *pbd, const int block_num)
{
        int num_pkts = pbd->h1.num_pkts, i;
        unsigned long bytes = 0;
        struct tpacket3_hdr *ppd;

        ppd = (struct tpacket3_hdr *) ((uint8_t *) pbd +
                                    pbd->h1.offset_to_first_pkt);
        for (i = 0; i < num_pkts; ++i) {
                bytes += ppd->tp_len;
                //handle_pkt(ppd);
                handle_pkt_test(ppd);

                ppd = (struct tpacket3_hdr *) ((uint8_t *) ppd +
                                            ppd->tp_next_offset);
        }

		//printf("Get %d Packets Once.\n", num_pkts);

        packets_total += num_pkts;
        bytes_total += bytes;
}

static void flush_block(struct block_desc *pbd)
{
        pbd->h1.block_status = TP_STATUS_KERNEL;
}

static void teardown_socket(struct ring *ring, int fd)
{
        munmap(ring->map, ring->req.tp_block_size * ring->req.tp_block_nr);
        free(ring->rd);
        close(fd);
}

static int private_hash_compare(const void *a, const void *b, void *udata) {
	HASH_NODE_KEY *a_key = (HASH_NODE_KEY *)a;
	HASH_NODE_KEY *b_key = (HASH_NODE_KEY *)b;

    //printf("[private_hash_compare]A:%d-%d-%d-%d   B:%d-%d-%d-%d \n", 
	//	a_key->sip, a_key->dip, a_key->sport, a_key->dport,
	//	b_key->sip, b_key->dip, b_key->sport, b_key->dport);

	if (a_key->sip == b_key->sip &&
		a_key->dip == b_key->dip &&
		a_key->sport == b_key->sport &&
		a_key->dport == b_key->dport)
		return 0;

	return -1;
}

static uint64_t private_hash_key(const void *item, uint64_t seed0, uint64_t seed1) {
    HASH_NODE_DATA *item_hash = (HASH_NODE_DATA *)item;
    return (item_hash->key.sip ^ item_hash->key.dip ^ item_hash->key.sport ^ item_hash->key.dport);
	//return hashmap_sip(item, sizeof(HASH_NODE_KEY), seed0, seed1);
}

void shell_sort(int arr[], int len) {
    int gap, i, j;
    int temp;
    for (gap = len >> 1; gap > 0; gap = gap >> 1)
        for (i = gap; i < len; i++) {
            temp = arr[i];
            for (j = i - gap; j >= 0 && arr[j] < temp; j -= gap)
                arr[j + gap] = arr[j];
            arr[j + gap] = temp;
        }
}

bool hash_iter(const void *item, void *udata) {
	if (item == NULL) {
		return true;
	}

	HASH_NODE_DATA *data = item;
	int *cnt = udata;
	int cur_cnt = (*cnt)++;
	
	printf("[hash_iter]Sip:%d.%d.%d.%d Sport:%u Dip:%d.%d.%d.%d Dport:%u Status %d Time %lu, CurrentHashCnt %d Time %u. \n",
						(data->key.sip >> 24) & 0xff, 
						(data->key.sip >> 16) & 0xff, 
						(data->key.sip >> 8) & 0xff, 
						(data->key.sip >> 0) & 0xff, 
						data->key.sport,
						(data->key.dip >> 24) & 0xff, 
						(data->key.dip >> 16) & 0xff, 
						(data->key.dip >> 8) & 0xff, 
						(data->key.dip >> 0) & 0xff, 
						data->key.dport, data->status, data->time, cur_cnt, time(NULL));

	return true;
}


static void* calc_delay_thread(void *para) {
	printf("Start thread calc_delay_thread .... \n");
	
	while (1) {
		sleep(1);
		int cnt = hashmap_count(hash_map);
		if (cnt == 0) {
			printf("Hash No Data .... \n");
			continue;
		}else {
			printf("Hash Cnt %d \n", cnt);
		}

		int hash_cnt = 0;
		HASH_NODE_DATA *data = NULL;
		hashmap_scan(hash_map, hash_iter, &hash_cnt);
	}
}

int main(int argc, char **argp)
{
        int fd, err;
        socklen_t len;
        struct ring ring;
        struct pollfd pfd;
        unsigned int block_num = 0, blocks = 64;
        struct block_desc *pbd;
        struct tpacket_stats_v3 stats;

        if (argc != 3) {
                fprintf(stderr, "Usage: %s INTERFACE dest_port\n", argp[0]);
                return EXIT_FAILURE;
        }

		g_dest_port = atoi(argp[2]);
		printf("================> Dest Port %d \n", g_dest_port);

		hash_map = hashmap_new(sizeof(HASH_NODE_DATA), (8*1024), time(NULL), time(NULL), private_hash_key, private_hash_compare, NULL, NULL);
		if (NULL == hash_map){
			fprintf(stderr, "Failed to hashmap_new. \n");
			return EXIT_FAILURE;
		}

		pthread_t threadID;
		if (0 != pthread_create(&threadID, NULL, calc_delay_thread, NULL)) {
			printf("Create calc_delay_thread Error ! \n");
			return -1;
		}

        signal(SIGINT, sighandler);

        memset(&ring, 0, sizeof(ring));
        fd = setup_socket(&ring, argp[1]);
        assert(fd > 0);

        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = POLLIN | POLLERR;
        pfd.revents = 0;

        while (likely(!sigint)) {
                pbd = (struct block_desc *) ring.rd[block_num].iov_base;
				if (pbd == NULL) {
					printf("NULL pbd \n");
					continue;
				}

                if ((pbd->h1.block_status & TP_STATUS_USER) == 0) {
                        poll(&pfd, 1, -1);
                        continue;
                }

                walk_block(pbd, block_num);
                flush_block(pbd);
                block_num = (block_num + 1) % blocks;
        }

        len = sizeof(stats);
        err = getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
        if (err < 0) {
                perror("getsockopt");
                exit(1);
        }

        fflush(stdout);
        printf("\nReceived %u packets, %lu bytes, %u dropped, freeze_q_cnt: %u\n",
            stats.tp_packets, bytes_total, stats.tp_drops,
            stats.tp_freeze_q_cnt);

		//printf("\nTotal Num %ld , AVG Cost %ld us. \n", total_num, total_delay_us / total_num);	

        teardown_socket(&ring, fd);
        return 0;
}
