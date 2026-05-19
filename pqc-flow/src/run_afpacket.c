// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Copyright (c) 2025 Graziano Labs Corp.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "afpacket_capture.h"
#include "l3_utils.h"
#include "flow.h"
#include "tiny_hash.h"
#include "ssh_kex_sniffer.h"
#include "tls_pqc_sniffer.h"

#ifndef TPACKET_ALIGNMENT
#define TPACKET_ALIGNMENT 16
#endif
#ifndef TPACKET_ALIGN
#define TPACKET_ALIGN(x) (((x)+TPACKET_ALIGNMENT-1)&~(TPACKET_ALIGNMENT-1))
#endif

/* Canonical flow key for bidirectional tracking */
typedef struct {
  uint8_t  ver;   // 4 or 6
  uint8_t  proto; // TCP/UDP
  uint8_t  pad[2];
  struct in6_addr a, b; // canonical: lower first (v4-in-v6 format)
  uint16_t sp, dp;      // canonical: lower endpoint first
} FlowKey;

typedef struct {
  FlowKey key;
  FlowRecord fr;
  NdpiFlowWrap fw;
  ssh_kex_fsm ssh_fsm;  // SSH KEX parser state
  tls_pqc_fsm tls_fsm;  // TLS PQC parser state
  uint8_t exported;     // flag to avoid duplicate exports
  uint8_t client_is_src; // 1 if canonical src is the SSH client (ephemeral port)
  uint8_t client_determined; // 1 after first packet sets client_is_src
  uint64_t first_seen_ts;    // microseconds
  uint8_t smac[6], dmac[6];  // Ethernet MAC addresses (canonical order)
  uint8_t has_macs;          // 1 if MAC addresses captured
} FTEntry;

static th_table *ft = NULL;

static inline void v4_to_v6(uint32_t v4, struct in6_addr *v6) {
  memset(v6, 0, sizeof(*v6));
  v6->s6_addr[10]=0xff; v6->s6_addr[11]=0xff;
  memcpy(&v6->s6_addr[12], &v4, 4);
}

/* Compare two in6_addr (works for v4-in-v6 too) */
static int addr_cmp(const struct in6_addr *a, const struct in6_addr *b) {
  return memcmp(a, b, sizeof(*a));
}

/*
 * Build canonical flow key (lower endpoint first) and compute packet direction.
 * Returns: direction = 0 if packet matches canonical src->dst, 1 if reversed
 */
static int make_flow_key(uint8_t ver, uint8_t proto,
                         const struct in6_addr *src, const struct in6_addr *dst,
                         uint16_t sp, uint16_t dp,
                         FlowKey *out)
{
  memset(out, 0, sizeof(*out));
  out->ver = ver;
  out->proto = proto;

  /* Compare addresses, then ports if addresses equal */
  int cmp = addr_cmp(src, dst);
  int swap = 0;
  if (cmp < 0) {
    swap = 0;  /* src < dst: keep as-is */
  } else if (cmp > 0) {
    swap = 1;  /* src > dst: swap */
  } else {
    /* Same address: compare ports */
    swap = (sp > dp) ? 1 : 0;
  }

  if (!swap) {
    out->a = *src; out->b = *dst;
    out->sp = sp; out->dp = dp;
    return 0;  /* packet direction matches canonical */
  } else {
    out->a = *dst; out->b = *src;
    out->sp = dp; out->dp = sp;
    return 1;  /* packet direction is reversed */
  }
}

static FTEntry* ft_lookup_or_add(const FlowKey *k) {
  if(!ft) ft = th_create(4096);
  FTEntry *e = (FTEntry*)th_get(ft, k, sizeof(*k));
  if(!e){
    e = (FTEntry*)calloc(1,sizeof(*e));
    e->key = *k;
    e->fr.src_port=k->sp; e->fr.dst_port=k->dp; e->fr.l4_proto=k->proto;
    e->exported = 0;
    e->client_determined = 0;
    e->has_macs = 0;
    e->first_seen_ts = 0;
    ssh_kex_init(&e->ssh_fsm);  // Initialize SSH KEX parser
    tls_pqc_init(&e->tls_fsm);  // Initialize TLS PQC parser
    th_put(ft, &e->key, sizeof(e->key), e);
  }
  return e;
}

static void export_jsonl(const FTEntry *e) {
  const FlowMeta *m = &e->fw.meta;
  char sip[64], dip[64];
  if(e->key.ver==4) {
    struct in_addr s4, d4;
    memcpy(&s4, &e->key.a.s6_addr[12], 4);
    memcpy(&d4, &e->key.b.s6_addr[12], 4);
    inet_ntop(AF_INET, &s4, sip, sizeof(sip));
    inet_ntop(AF_INET, &d4, dip, sizeof(dip));
  } else {
    inet_ntop(AF_INET6, &e->key.a, sip, sizeof(sip));
    inet_ntop(AF_INET6, &e->key.b, dip, sizeof(dip));
  }

  /* Format MAC addresses */
  char smac[18] = "", dmac[18] = "";
  if(e->has_macs) {
    snprintf(smac, sizeof(smac), "%02x:%02x:%02x:%02x:%02x:%02x",
             e->smac[0], e->smac[1], e->smac[2], e->smac[3], e->smac[4], e->smac[5]);
    snprintf(dmac, sizeof(dmac), "%02x:%02x:%02x:%02x:%02x:%02x",
             e->dmac[0], e->dmac[1], e->dmac[2], e->dmac[3], e->dmac[4], e->dmac[5]);
  }

  printf("{\"live\":1,\"ts_us\":%llu,\"proto\":%u,\"sip\":\"%s\",\"dip\":\"%s\",\"sp\":%u,\"dp\":%u,"
         "\"smac\":\"%s\",\"dmac\":\"%s\","
         "\"pqc_flags\":%u,\"pqc_reason\":\"%s\","
         "\"tls_negotiated_group\":\"%s\",\"tls_server_name\":\"%s\",\"tls_cipher_suite\":\"%s\","
         "\"tls_cert_fingerprint\":\"%s\",\"tls_cert_subject\":\"%s\",\"tls_cert_issuer\":\"%s\","
         "\"ssh_kex_negotiated\":\"%s\","
         "\"quic_tls_negotiated_group\":\"%s\",\"ike_ke_chosen\":\"%s\"}\n",
         (unsigned long long)e->first_seen_ts,
         e->fr.l4_proto, sip, dip, e->fr.src_port, e->fr.dst_port,
         smac, dmac,
         m->pqc_flags, m->pqc_reason,
         m->tls_negotiated_group, m->tls_server_name, m->tls_cipher_suite,
         m->tls_cert_fingerprint, m->tls_cert_subject, m->tls_cert_issuer,
         m->ssh_kex_negotiated,
         m->quic_tls_negotiated_group, m->ike_ke_chosen);
  fflush(stdout);
}

static inline int likely_handshake_port(uint8_t proto, uint16_t port) {
  if(proto == IPPROTO_TCP) return (port==443 || port==22);
  else if(proto == IPPROTO_UDP) return (port==443 || port==500 || port==4500 || port==51820);
  return 0;
}

static inline int is_handshake_flow(uint8_t proto, uint16_t sp, uint16_t dp) {
  return likely_handshake_port(proto, sp) || likely_handshake_port(proto, dp);
}

int run_afpacket(const char *iface, NdpiCtx *ctx, int fanout_id, int snaplen) {
  /* Debug counters */
  static uint64_t pkt_total = 0, pkt_filtered = 0, flows_created = 0, exports_made = 0;

  int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if(s < 0) { perror("socket(AF_PACKET)"); return -1; }

  fprintf(stderr, "[LIVE] Capturing on %s (TPACKET_V3)...\n", iface);

  int ver = TPACKET_V3;
  if(setsockopt(s, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver)) < 0) {
    perror("setsockopt(PACKET_VERSION)"); close(s); return -2;
  }

  if(fanout_id > 0) {
    int fanout = (fanout_id & 0xFFFF) | (PACKET_FANOUT_HASH << 16);
    if(setsockopt(s, SOL_PACKET, PACKET_FANOUT, &fanout, sizeof(fanout)) < 0) {
      perror("setsockopt(PACKET_FANOUT)"); /* continue without fanout */;
    }
  }

  int desired_snap = (snaplen > 0) ? snaplen : 2048;
  int frame_sz = TPACKET_ALIGN(desired_snap + 256); // room for headers
  if(frame_sz < 2048) frame_sz = 2048;

  struct tpacket_req3 req; memset(&req,0,sizeof(req));
  req.tp_frame_size = frame_sz;
  req.tp_block_size = frame_sz * 1024;  // 1024 frames per block
  req.tp_block_nr   = 64;
  req.tp_frame_nr   = (req.tp_block_size / req.tp_frame_size) * req.tp_block_nr;
  req.tp_retire_blk_tov = 60; // ms

  if(setsockopt(s, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
    perror("setsockopt(PACKET_RX_RING)"); close(s); return -3;
  }

  size_t mmap_len = (size_t)req.tp_block_size * req.tp_block_nr;
  void *ring = mmap(NULL, mmap_len, PROT_READ|PROT_WRITE, MAP_SHARED, s, 0);
  if(ring == MAP_FAILED) { perror("mmap"); close(s); return -4; }

  struct sockaddr_ll sll; memset(&sll,0,sizeof(sll));
  sll.sll_family   = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex  = if_nametoindex(iface);
  if(sll.sll_ifindex == 0) { fprintf(stderr,"if_nametoindex(%s) failed\n", iface); return -5; }
  if(bind(s, (struct sockaddr*)&sll, sizeof(sll)) < 0) { perror("bind"); return -6; }

  struct pollfd pfd = { .fd = s, .events = POLLIN };
  uint8_t *base = (uint8_t*)ring;
  #define BLOCK_AT(idx) ((struct tpacket_block_desc*)(base + (size_t)idx*req.tp_block_size))

  while(1) {
    int n = poll(&pfd, 1, 1000);
    if(n < 0) { if(errno==EINTR) continue; perror("poll"); break; }
    if(n == 0) continue;
    for (uint32_t b = 0; b < req.tp_block_nr; b++) {
      struct tpacket_block_desc *bd = BLOCK_AT(b);
      if ((bd->hdr.bh1.block_status & TP_STATUS_USER) == 0) continue;

      uint8_t *p = (uint8_t*)bd + bd->hdr.bh1.offset_to_first_pkt;
      for (uint32_t i=0; i<bd->hdr.bh1.num_pkts; i++) {
        struct tpacket3_hdr *h = (struct tpacket3_hdr*)p;
        const uint8_t *l2 = (const uint8_t*)h + h->tp_mac;
        uint32_t caplen = h->tp_snaplen;
        uint32_t l3_off = 0;
        uint16_t et = l2_advance_to_l3(l2, caplen, &l3_off);
        if(et == 0) { p += h->tp_next_offset; continue; }

        const uint8_t *l3p = l2 + l3_off;
        uint32_t l3len = caplen > l3_off ? (caplen - l3_off) : 0;
        uint8_t ver=0, l4=0;
        struct in6_addr a6={{0}}, b6={{0}};
        uint16_t sp=0, dp=0;

        if(et == ETH_P_IP && l3len >= 20) {
          const struct ip *ip4 = (const struct ip*)l3p;
          ver=4; l4=ip4->ip_p;
          uint32_t s4 = *(const uint32_t*)&ip4->ip_src;
          uint32_t d4 = *(const uint32_t*)&ip4->ip_dst;
          v4_to_v6(s4, &a6); v4_to_v6(d4, &b6);
          uint16_t iphl = ip4->ip_hl*4;
          if(l3len < iphl) { p += h->tp_next_offset; continue; }
          const uint8_t *l4p = l3p + iphl;
          uint32_t l4len = l3len - iphl;
          if(l4 == IPPROTO_TCP && l4len >= 20) {
            const struct tcphdr *th = (const struct tcphdr*)l4p;
            sp = ntohs(th->source); dp = ntohs(th->dest);
          } else if(l4 == IPPROTO_UDP && l4len >= 8) {
            const struct udphdr *uh = (const struct udphdr*)l4p;
            sp = ntohs(uh->source); dp = ntohs(uh->dest);
          } else { p += h->tp_next_offset; continue; }
        } else if(et == ETH_P_IPV6 && l3len >= 40) {
          const struct ip6_hdr *ip6 = (const struct ip6_hdr*)l3p;
          ver=6; l4=ip6->ip6_nxt;
          a6 = ip6->ip6_src; b6 = ip6->ip6_dst;
          const uint8_t *l4p = l3p + 40;
          uint32_t l4len = l3len - 40;
          if(l4 == IPPROTO_TCP && l4len >= 20) {
            const struct tcphdr *th = (const struct tcphdr*)l4p;
            sp = ntohs(th->source); dp = ntohs(th->dest);
          } else if(l4 == IPPROTO_UDP && l4len >= 8) {
            const struct udphdr *uh = (const struct udphdr*)l4p;
            sp = ntohs(uh->source); dp = ntohs(uh->dest);
          } else { p += h->tp_next_offset; continue; }
        } else { p += h->tp_next_offset; continue; }

        pkt_total++;

        /* Filter: keep only handshake-related traffic (check both ports) */
        if(!is_handshake_flow(l4, sp, dp)) {
          pkt_filtered++;
          p += h->tp_next_offset;
          continue;
        }

        /* Build canonical key and compute direction */
        FlowKey fk;
        int direction = make_flow_key(ver, l4, &a6, &b6, sp, dp, &fk);

        int is_new = (th_get(ft, &fk, sizeof(fk)) == NULL);
        FTEntry *e = ft_lookup_or_add(&fk);
        if(is_new) flows_created++;

        uint64_t ts_us = (uint64_t)h->tp_sec*1000000ULL + h->tp_nsec/1000ULL;

        /* Capture timestamp and MACs on first packet */
        if(e->first_seen_ts == 0) {
          e->first_seen_ts = ts_us;
          /* Extract MAC addresses from Ethernet header (l2 points to L2)
           * Ethernet: [dst_mac:6][src_mac:6][ethertype:2]
           * Apply canonical ordering based on packet direction */
          if(caplen >= 14) {
            const uint8_t *eth_src = l2 + 6;
            const uint8_t *eth_dst = l2 + 0;
            if(direction == 0) {
              /* Packet matches canonical order */
              memcpy(e->smac, eth_src, 6);
              memcpy(e->dmac, eth_dst, 6);
            } else {
              /* Packet is reversed */
              memcpy(e->smac, eth_dst, 6);
              memcpy(e->dmac, eth_src, 6);
            }
            e->has_macs = 1;
          }
        }

        /* Feed nDPI with L3 payload and computed direction */
        ndpi_glue_process_packet(ctx, &e->fw, l3p, l3len, ts_us, direction);

        /* Extract TCP payload for protocol-specific parsers */
        const uint8_t *tcp_pl = NULL;
        uint32_t tcp_plen = 0;
        if(l4 == IPPROTO_TCP) {
          extract_tcp_payload(l3p, l3len, ver, l4, &tcp_pl, &tcp_plen);
        }

        /* For SSH (TCP port 22), run our own KEX parser */
        if(l4 == IPPROTO_TCP && (dp == 22 || sp == 22) && tcp_pl && tcp_plen > 0) {
          /* Determine client direction on first packet */
          if(!e->client_determined) {
            e->client_is_src = (sp > 1024 && dp == 22) ? 1 : 0;
            e->client_determined = 1;
          }

          /* Compute from_client: if canonical src is client, then dir=0 means from_client */
          int from_client = (e->client_is_src) ? (direction == 0 ? 1 : 0) : (direction == 0 ? 0 : 1);

          char kex_alg[256] = {0};
          sshkex_rc rc = ssh_kex_feed(&e->ssh_fsm, tcp_pl, tcp_plen, from_client, kex_alg, sizeof(kex_alg));

          if(rc == SSHKEX_FOUND_PQC || rc == SSHKEX_FOUND_NONPQC) {
            if(kex_alg[0]) {
              strncpy(e->fw.meta.ssh_kex_negotiated, kex_alg, sizeof(e->fw.meta.ssh_kex_negotiated)-1);
              e->fw.meta.ssh_kex_negotiated[sizeof(e->fw.meta.ssh_kex_negotiated)-1] = '\0';
            }
            if(rc == SSHKEX_FOUND_PQC) {
              e->fw.meta.pqc_flags |= PQC_F_SSH_KEX;
              /* pqc_from_strings() will add ssh:sntrup via pqc_mark_reason() which deduplicates */
            }
          }
        }

        /* For TLS (TCP port 443), run our own TLS parser */
        if(l4 == IPPROTO_TCP && (dp == 443 || sp == 443) && tcp_pl && tcp_plen > 0) {
          char tls_group[64] = {0};
          tlspqc_rc rc = tls_pqc_feed(&e->tls_fsm, tcp_pl, tcp_plen, tls_group, sizeof(tls_group));

          if(rc == TLSPQC_FOUND_PQC || rc == TLSPQC_FOUND_CLASSIC) {
            if(tls_group[0]) {
              strncpy(e->fw.meta.tls_negotiated_group, tls_group, sizeof(e->fw.meta.tls_negotiated_group)-1);
              e->fw.meta.tls_negotiated_group[sizeof(e->fw.meta.tls_negotiated_group)-1] = '\0';
            }
            if(rc == TLSPQC_FOUND_PQC) {
              e->fw.meta.pqc_flags |= PQC_F_TLS_GROUP;
              /* pqc_from_strings() will mark TLS PQC tokens */
            }
            /* Copy TLS metadata from FSM to FlowMeta for export */
            if(e->tls_fsm.server_name[0]) {
              strncpy(e->fw.meta.tls_server_name, e->tls_fsm.server_name, sizeof(e->fw.meta.tls_server_name)-1);
            }
            if(e->tls_fsm.cipher_suite[0]) {
              strncpy(e->fw.meta.tls_cipher_suite, e->tls_fsm.cipher_suite, sizeof(e->fw.meta.tls_cipher_suite)-1);
            }
            if(e->tls_fsm.cert_fingerprint[0]) {
              strncpy(e->fw.meta.tls_cert_fingerprint, e->tls_fsm.cert_fingerprint, sizeof(e->fw.meta.tls_cert_fingerprint)-1);
            }
            if(e->tls_fsm.cert_subject[0]) {
              strncpy(e->fw.meta.tls_cert_subject, e->tls_fsm.cert_subject, sizeof(e->fw.meta.tls_cert_subject)-1);
            }
            if(e->tls_fsm.cert_issuer[0]) {
              strncpy(e->fw.meta.tls_cert_issuer, e->tls_fsm.cert_issuer, sizeof(e->fw.meta.tls_cert_issuer)-1);
            }
          }
        }

        /* Derive PQC flags from nDPI metadata (TLS/QUIC/IKE) */
        pqc_from_strings(&e->fw.meta, "tls",
          e->fw.meta.tls_supported_groups, e->fw.meta.tls_negotiated_group,
          e->fw.meta.tls_sig_algs, e->fw.meta.tls_server_sigalg);
        pqc_from_strings(&e->fw.meta, "ssh",
          e->fw.meta.ssh_kex_offered, e->fw.meta.ssh_kex_negotiated,
          e->fw.meta.ssh_hostkey_offered, e->fw.meta.ssh_sig_alg);
        pqc_from_strings(&e->fw.meta, "quic",
          e->fw.meta.quic_tls_supported_groups, e->fw.meta.quic_tls_negotiated_group,
          e->fw.meta.quic_tls_sig_algs, NULL);

        /* Export when handshake completes */
        if(!e->exported && (ndpi_glue_handshake_done(&e->fw) || e->ssh_fsm.st == SSH_S_DONE || e->tls_fsm.st == TLS_S_DONE)) {
          export_jsonl(e);
          e->exported = 1;
          exports_made++;
          if(exports_made <= 5) {
            fprintf(stderr, "[LIVE] Export #%llu: %s:%u -> %s:%u\n",
                    (unsigned long long)exports_made,
                    (direction == 0 ? "client" : "server"), (direction == 0 ? sp : dp),
                    (direction == 0 ? "server" : "client"), (direction == 0 ? dp : sp));
          }
        }

        /* Periodic stats */
        if(pkt_total % 1000 == 0) {
          fprintf(stderr, "[LIVE] Stats: %llu pkts, %llu filtered, %llu flows, %llu exports\n",
                  (unsigned long long)pkt_total, (unsigned long long)pkt_filtered,
                  (unsigned long long)flows_created, (unsigned long long)exports_made);
        }

        p += h->tp_next_offset;
      }
      bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
    }
  }

  fprintf(stderr, "[LIVE] Shutting down. Final stats: %llu pkts, %llu flows, %llu exports\n",
          (unsigned long long)pkt_total, (unsigned long long)flows_created, (unsigned long long)exports_made);

  munmap(ring, mmap_len);
  close(s);
  return 0;
}
