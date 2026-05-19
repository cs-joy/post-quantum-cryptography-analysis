// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Copyright (c) 2025 Graziano Labs Corp.
 */

#ifndef L3_UTILS_H
#define L3_UTILS_H
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

static inline uint16_t l2_advance_to_l3(const uint8_t *l2, uint32_t caplen, uint32_t *l3_off) {
  if(caplen < 14) return 0;
  uint16_t et = (uint16_t)((l2[12] << 8) | l2[13]);
  uint32_t off = 14;
  for(int i=0;i<2;i++){
    if(et == 0x8100 || et == 0x88A8) {
      if(caplen < off+4) return 0;
      et = (uint16_t)((l2[off+2] << 8) | l2[off+3]);
      off += 4;
    } else break;
  }
  *l3_off = off;
  return et;
}

/**
 * Extract TCP payload from L3 packet (IP header start).
 * @param l3      Pointer to IP header (v4 or v6)
 * @param l3len   Length from IP header to end of capture
 * @param ipver   IP version (4 or 6)
 * @param l4proto L4 protocol number (should be IPPROTO_TCP)
 * @param tcp_payload_out  Output: pointer to TCP payload (set to NULL if not TCP or no payload)
 * @param tcp_plen_out     Output: TCP payload length
 * @return 1 on success, 0 if not TCP or malformed
 */
static inline int extract_tcp_payload(const uint8_t *l3, uint32_t l3len, uint8_t ipver, uint8_t l4proto,
                                      const uint8_t **tcp_payload_out, uint32_t *tcp_plen_out) {
  *tcp_payload_out = NULL;
  *tcp_plen_out = 0;

  if(l4proto != IPPROTO_TCP) return 0;

  const uint8_t *l4ptr = NULL;
  uint32_t l4len = 0;

  if(ipver == 4) {
    if(l3len < 20) return 0;
    const struct ip *ip4 = (const struct ip*)l3;
    uint16_t ihl = (ip4->ip_hl & 0x0F) * 4;
    if(l3len < ihl) return 0;
    l4ptr = l3 + ihl;
    l4len = l3len - ihl;
  } else if(ipver == 6) {
    if(l3len < 40) return 0;
    l4ptr = l3 + 40;
    l4len = l3len - 40;
  } else {
    return 0;
  }

  if(l4len < 20) return 0; /* minimum TCP header */

  const struct tcphdr *th = (const struct tcphdr*)l4ptr;
  uint16_t tcp_hlen = ((th->doff) * 4);
  if(l4len < tcp_hlen) return 0;

  *tcp_payload_out = l4ptr + tcp_hlen;
  *tcp_plen_out = l4len - tcp_hlen;
  return 1;
}

#endif
