#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>

#define IF_NAME "enp8s0"  // Change to your interface name
#define ETH_P_SV 0x88BA  // EtherType for Sampled Values
#define DEST_MAC "\x01\x0C\xCD\x04\x00\x01"  // IEC 61850-9-2 LE multicast address
#define SRC_MAC_LEN 6
#define SV_FRAME_LEN 126

//static uint8_t send_ring_buffer[4096] = {};
//static size_t ring_read = 0;
//static size_t ring_write = 0;
//static bool wrap_buffer = false;

#pragma pack(1)

struct ethernet_frame_header {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
};

struct sv_frame_header {
    uint16_t APPID;
    uint16_t msg_len;
    uint16_t reserved1;
    uint16_t reserved2;
};

struct savPdu_header {
    uint8_t tag; /* for 9-2LE always 0x60 */
    uint8_t len; /* for 9-2LE always 0x53 + length of svID string (0x66) */
    uint8_t tag_noASDU; /* for 9-2LE always 0x80 */
    uint8_t len_noASDU; /* for 9-2LE always 0x01 */
    uint8_t noASDU;
    uint8_t tag_ASDU; /* 0x30 */
    uint8_t len_ASDU; /* 0x5f */
    uint8_t tag_seqASDU; /* for 9-2LE always 0xa2 */
    uint8_t len_seqASDU; /* for 9-2LE always len - 0x05 (0x61) */
};

struct asdu_header {
    uint8_t tag; /* for 9-2LE always 0x80 */
    uint8_t len; /* length of svID string (buffer) */
    char svID[14]; // this is not generic and has to be changed later on for now: AA1E1Q01MU0101
    uint8_t tag_smpCnt; /* for 9-2LE always 0x82 */
    uint8_t len_smpCnt; /* for 9-2LE likely 0x02 otherwise implementation has to be changed */
    uint16_t smpCnt;
    uint8_t tag_confRev; /* for 9-2LE always 0x83 */
    uint8_t len_confRev; /* for 9-2LE likely 0x04 otherwise implementation has to be changed */
    uint32_t confRev;
    uint8_t tag_smpSynch; /* for 9-2LE always 0x85 */
    uint8_t len_smpSynch; /* for 9-2LE likely 0x01 otherwise implementation has to be changed */
    uint8_t smpSynch;
};

struct asdu_le_seqData {
    uint8_t tag;
    uint8_t len;
    int32_t l1_amp_mag;
    int32_t l1_amp_q;
    int32_t l2_amp_mag;
    int32_t l2_amp_q;
    int32_t l3_amp_mag;
    int32_t l3_amp_q;
    int32_t n_amp_mag;
    int32_t n_amp_q;
    int32_t l1_volt_mag;
    int32_t l1_volt_q;
    int32_t l2_volt_mag;
    int32_t l2_volt_q;
    int32_t l3_volt_mag;
    int32_t l3_volt_q;
    int32_t n_volt_mag;
    int32_t n_volt_q;
};

struct sv_frame {
    struct ethernet_frame_header eth;
    struct sv_frame_header sv;
    struct savPdu_header savPdu;
    struct asdu_header asdu_head;
    struct asdu_le_seqData asdu1;
};

#pragma pack()

int main() {
    int sockfd = 0;
    struct ifreq if_idx = {};
    struct ifreq if_mac = {};
    struct sockaddr_ll socket_address = {};
    struct sv_frame sv_frame = {
        .eth.dest_mac           = { 0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01 },
        .eth.src_mac            = { 0x20, 0xb7, 0xc0, 0x00, 0x57, 0xc7 },
        .eth.ethertype          = htons(0x88ba),
        .sv.APPID               = htons(0x4000),
        .sv.msg_len             = htons(0x0070),
        .sv.reserved1           = 0x00,
        .sv.reserved2           = 0x00,
        .savPdu.tag             = 0x60,
        .savPdu.len             = 0x66,
        .savPdu.tag_noASDU      = 0x80,
        .savPdu.len_noASDU      = 0x01,
        .savPdu.noASDU          = 0x01,
        .savPdu.tag_ASDU        = 0xa2,
        .savPdu.len_ASDU        = 0x61,
        .savPdu.tag_seqASDU     = 0x30,
        .savPdu.len_seqASDU     = 0x5f,
        .asdu_head.tag          = 0x80,
        .asdu_head.len          = 0x0e,
        .asdu_head.svID         = "AA1E1Q01MU0101",
        .asdu_head.tag_smpCnt   = 0x82,
        .asdu_head.len_smpCnt   = 0x02,
        .asdu_head.smpCnt       = 0x00,
        .asdu_head.tag_confRev  = 0x83,
        .asdu_head.len_confRev  = 0x04,
        .asdu_head.confRev      = htonl(0x00000001),
        .asdu_head.tag_smpSynch = 0x85,
        .asdu_head.len_smpSynch = 0x01,
        .asdu_head.smpSynch     = 0x00,
        .asdu1.tag              = 0x87,
        .asdu1.len              = 0x40
    };

    // Open raw socket
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        perror("socket");
        exit(1);
    }

    // Get interface index
    strncpy(if_idx.ifr_name, IF_NAME, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
        perror("SIOCGIFINDEX");
        exit(1);
    }

    // Get MAC address
    strncpy(if_mac.ifr_name, IF_NAME, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) {
        perror("SIOCGIFHWADDR");
        exit(1);
    }

    // Prepare socket address
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, DEST_MAC, 6);

    struct timespec next_time = {};
    clock_gettime(CLOCK_MONOTONIC, &next_time);
    // Send loop
    while (1) {
        if (sendto(sockfd, &sv_frame, sizeof(sv_frame), 0,
                   (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
            perror("sendto");
            break;
        }
        next_time.tv_nsec += 250000l;
        next_time.tv_sec += next_time.tv_nsec / 1000000000l;
        next_time.tv_nsec %= 1000000000l;
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next_time, nullptr);
    }

    close(sockfd);
    return 0;
}
