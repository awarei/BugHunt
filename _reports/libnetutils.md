---
layout: post
title: "Android libnetutils packet.c"
category: security
tags: [stb, intissues]
date: 2019-02-23
---

# Exercise
```c
int receive_packet(int s, struct dhcp_msg *msg)
{
    int nread;
    int is_valid;
    struct dhcp_packet {
        struct iphdr ip;
        struct udphdr udp;
        struct dhcp_msg dhcp;
    } packet;
    int dhcp_size;
    uint32_t sum;
    uint16_t temp;
    uint32_t saddr, daddr;
    nread = read(s, &packet, sizeof(packet));
    if (nread < 0) {
        return -1;
    }
    /*
     * The raw packet interface gives us all packets received by the
     * network interface. We need to filter out all packets that are
     * not meant for us.
     */
    is_valid = 0;
    if (nread < (int)(sizeof(struct iphdr) + sizeof(struct udphdr))) {
#if VERBOSE
        ALOGD("Packet is too small (%d) to be a UDP datagram", nread);
#endif
    } else if (packet.ip.version != IPVERSION || packet.ip.ihl != (sizeof(packet.ip) >> 2)) {
#if VERBOSE
        ALOGD("Not a valid IP packet");
#endif
    } else if (nread < ntohs(packet.ip.tot_len)) {
#if VERBOSE
        ALOGD("Packet was truncated (read %d, needed %d)", nread, ntohs(packet.ip.tot_len));
#endif
    } else if (packet.ip.protocol != IPPROTO_UDP) {
#if VERBOSE
        ALOGD("IP protocol (%d) is not UDP", packet.ip.protocol);
#endif
    } else if (packet.udp.dest != htons(PORT_BOOTP_CLIENT)) {
#if VERBOSE
        ALOGD("UDP dest port (%d) is not DHCP client", ntohs(packet.udp.dest));
#endif
    } else {
        is_valid = 1;
    }
    if (!is_valid) {
        return -1;
    }
    /* Seems like it's probably a valid DHCP packet */
    /* validate IP header checksum */
    sum = finish_sum(checksum(&packet.ip, sizeof(packet.ip), 0));
    if (sum != 0) {
        ALOGW("IP header checksum failure (0x%x)", packet.ip.check);
        return -1;
    }
    /*
     * Validate the UDP checksum.
     * Since we don't need the IP header anymore, we "borrow" it
     * to construct the pseudo header used in the checksum calculation.
     */
    dhcp_size = ntohs(packet.udp.len) - sizeof(packet.udp);
    saddr = packet.ip.saddr;
    daddr = packet.ip.daddr;
    nread = ntohs(packet.ip.tot_len);
    memset(&packet.ip, 0, sizeof(packet.ip));
    packet.ip.saddr = saddr;
    packet.ip.daddr = daddr;
    packet.ip.protocol = IPPROTO_UDP;
    packet.ip.tot_len = packet.udp.len;
    temp = packet.udp.check;
    packet.udp.check = 0;
    sum = finish_sum(checksum(&packet, nread, 0));
    packet.udp.check = temp;
    if (!sum)
        sum = finish_sum(sum);
    if (temp != sum) {
        ALOGW("UDP header checksum failure (0x%x should be 0x%x)", sum, temp);
        return -1;
    }
    memcpy(msg, &packet.dhcp, dhcp_size);
    return dhcp_size;
}
```

# Explanation
There is an integer underflow due to subtraction operation.

# Refs
- [https://android.googlesource.com/platform/system/core/+/b71335264a7c3629f80b7bf1f87375c75c42d868%5E%21/#F0](https://android.googlesource.com/platform/system/core/+/b71335264a7c3629f80b7bf1f87375c75c42d868%5E%21/#F0)
- [https://source.android.com/security/bulletin/2018-01-01](https://source.android.com/security/bulletin/2018-01-01)
- CVE-2017-13208