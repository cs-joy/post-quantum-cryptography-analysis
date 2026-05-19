// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Copyright (c) 2025 Graziano Labs Corp.
 */

#define _GNU_SOURCE
#include "ssh_kex_sniffer.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>

/* ---- tiny utils ---- */
static inline uint32_t be32(const uint8_t *p){
  return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|((uint32_t)p[3]);
}

/* name-list = uint32 len; byte[len] CSV of names (RFC 4251 s.5, RFC 4253 s.7) */
static int parse_namelist(const uint8_t *p, size_t n, const char **csv, uint32_t *L){
  if(n < 4) return 0;
  uint32_t len = be32(p);
  if(4u + len > n) return 0;
  *csv = (const char*)(p+4);
  *L   = len;
  return 1;
}

static int token_next(const char *s, size_t n, size_t *off, const char **tok, size_t *tlen){
  if(*off >= n) return 0;
  size_t i = *off, j = i;
  while(j < n && s[j] != ',') j++;
  *tok = s + i; *tlen = j - i;
  *off = (j < n ? j+1 : n);
  return 1;
}

/* Conservative PQC/hybrid matcher (expand as needed) */
static int is_pqc_kex_token(const char *t, size_t L){
  /* OpenSSH hybrid family; case-sensitive exact match or contains "sntrup" */
  if(L >= 6 && memmem(t, L, "sntrup", 6)) return 1;
  /* Future hooks:
     if(memmem(t,L,"kyber",5)) return 1;
     if(memmem(t,L,"ntrup",5)) return 1;
     if(memmem(t,L,"mlkem",5)) return 1;
  */
  return 0;
}

/* Skip to name-list at given index in KEXINIT and return offset to it.
 * KEXINIT name-lists: 0=kex_algorithms, 1=server_host_key_algorithms,
 * 2=encryption_c2s, 3=encryption_s2c, 4=mac_c2s, 5=mac_s2c, 6-9=compression/languages
 * Returns 0 on error, otherwise offset to the start of the name-list length field.
 */
static size_t kexinit_skip_to_namelist(const uint8_t *p, size_t n, int list_index) {
  if(n < 1 + 16) return 0;           /* type + cookie */
  if(p[0] != 20) return 0;           /* SSH_MSG_KEXINIT */
  size_t off = 1 + 16;               /* skip type byte + 16-byte cookie */

  for(int i = 0; i < list_index; i++) {
    if(off + 4 > n) return 0;
    uint32_t len = be32(p + off);
    off += 4 + len;
    if(off > n) return 0;
  }
  return off;
}

/* Extract first entry from a name-list at given index in KEXINIT.
 * Returns 1 on success, 0 on failure.
 */
static int kexinit_extract_namelist_first(const uint8_t *p, size_t n, int list_index,
                                          char *out, size_t cap) {
  size_t off = kexinit_skip_to_namelist(p, n, list_index);
  if(off == 0) return 0;

  const char *csv = NULL; uint32_t L = 0;
  if(!parse_namelist(p + off, n - off, &csv, &L)) return 0;

  /* Get first token from CSV */
  size_t it = 0;
  const char *tok = NULL; size_t tlen = 0;
  if(token_next(csv, L, &it, &tok, &tlen) && tlen > 0) {
    size_t m = (tlen < cap - 1) ? tlen : cap - 1;
    memcpy(out, tok, m);
    out[m] = '\0';
    return 1;
  }
  return 0;
}

/* Extract host key algorithm (list index 1) */
int kexinit_extract_hostkey(const uint8_t *p, size_t n, char *out, size_t cap) {
  return kexinit_extract_namelist_first(p, n, 1, out, cap);
}

/* Extract cipher algorithm (list index 2 = encryption_c2s, we use client's first offer) */
int kexinit_extract_cipher(const uint8_t *p, size_t n, char *out, size_t cap) {
  return kexinit_extract_namelist_first(p, n, 2, out, cap);
}

/* Extract MAC algorithm (list index 4 = mac_c2s) */
int kexinit_extract_mac(const uint8_t *p, size_t n, char *out, size_t cap) {
  return kexinit_extract_namelist_first(p, n, 4, out, cap);
}

/* Extract chosen (or first) KEX from KEXINIT "kex_algorithms" name-list */
static int kexinit_extract_kex(const uint8_t *p, size_t n, char *out, size_t cap, int *is_pqc){
  /* p points to payload starting at message code (0x14) */
  if(n < 1 + 16) return 0;           /* type + cookie */
  if(p[0] != 20) return 0;           /* SSH_MSG_KEXINIT */
  size_t off = 1 + 16;

  /* 1st name-list is kex_algorithms */
  const char *csv = NULL; uint32_t L = 0;
  if(!parse_namelist(p+off, n-off, &csv, &L)) return 0;

  /* Walk CSV; prefer the first PQC token; otherwise take the first entry */
  size_t it = 0; const char *tok = NULL; size_t tlen = 0;
  const char *first = NULL; size_t first_len = 0;

  while(token_next(csv, L, &it, &tok, &tlen)){
    if(first == NULL && tlen > 0){ first = tok; first_len = tlen; }
    if(is_pqc_kex_token(tok, tlen)){
      size_t m = (tlen < cap-1) ? tlen : cap-1;
      memcpy(out, tok, m); out[m] = '\0';
      *is_pqc = 1;
      return 1;
    }
  }

  if(first){
    size_t m = (first_len < cap-1) ? first_len : cap-1;
    memcpy(out, first, m); out[m] = '\0';
    *is_pqc = 0;
    return 1;
  }
  return 0;
}

/* Consume ASCII up to '\n' safely into dst[cap]. Returns 1 when line completed. */
static int append_line(char *dst, size_t *len, size_t cap, const uint8_t *p, size_t n, size_t *consumed){
  size_t i = 0;
  while(i < n){
    char c = (char)p[i++];
    if(*len+1 < cap) dst[(*len)++] = c; /* store, may include CR */
    if(c == '\n'){
      if(*len < cap) dst[*len] = '\0';
      *consumed = i;
      return 1;
    }
  }
  *consumed = i;
  return 0;
}

/* ---- Public FSM ---- */
sshkex_rc ssh_kex_feed(ssh_kex_fsm *f,
                       const uint8_t *payload, size_t plen,
                       int from_client,
                       char *out_alg, size_t out_cap)
{
  if(!payload || plen == 0) return SSHKEX_IN_PROGRESS;
  if(f->st == SSH_S_DONE)    { if(out_alg && f->chosen_kex[0]) { strncpy(out_alg, f->chosen_kex, out_cap); } return (f->chosen_kex[0] ? SSHKEX_FOUND_PQC : SSHKEX_FOUND_NONPQC); }
  if(f->st == SSH_S_FAIL)    return SSHKEX_FAIL;

  size_t off = 0;

  /* 1) Version lines (ASCII) — each side sends one, order arbitrary */
  if(f->st == SSH_S_START) f->st = from_client ? SSH_S_VERS_CL : SSH_S_VERS_SRV;

  if(f->st == SSH_S_VERS_CL || f->st == SSH_S_VERS_SRV){
    size_t c = 0;
    if(from_client && !f->cl_done){
      if(append_line(f->v_cl, &f->v_cl_len, sizeof(f->v_cl), payload, plen, &c)){
        f->cl_done = true;
      }
    } else if(!from_client && !f->sv_done){
      if(append_line(f->v_sv, &f->v_sv_len, sizeof(f->v_sv), payload, plen, &c)){
        f->sv_done = true;
      }
    }
    off += c;
    if(off < plen){
      /* extra bytes in this same segment belong to binary SSH; fall-through */
    }
    if(f->cl_done && f->sv_done) f->st = SSH_S_KEX_HDR;
    else return SSHKEX_IN_PROGRESS;
  }

  /* 2) Binary packet header: 4-byte packet_length (then padding_length is first byte of packet data) */
  if(f->st == SSH_S_KEX_HDR){
    while(f->hdr_have < 4 && off < plen){
      f->hdr[f->hdr_have++] = payload[off++];
    }
    if(f->hdr_have < 4) return SSHKEX_IN_PROGRESS;

    f->pkt_len = be32(f->hdr);

    /* sanity: packet_length should be reasonable */
    if(f->pkt_len < 8 || f->pkt_len > sizeof(f->body)){
      /* Packet too large or malformed - reset and try next packet */
      f->hdr_have = 0;
      return SSHKEX_IN_PROGRESS;
    }
    f->need_body = f->pkt_len;  /* packet_length bytes following the length field */
    f->got_body  = 0;
    f->st = SSH_S_KEX_PAY;
  }

  /* 3) Accumulate body bytes: packet_length bytes total */
  if(f->st == SSH_S_KEX_PAY){
    while(f->got_body < f->need_body && off < plen){
      f->body[f->got_body++] = payload[off++];
    }
    if(f->got_body < f->need_body) return SSHKEX_IN_PROGRESS;

    /* Body layout: [padding_length:1][payload][random_padding] */
    /* packet_length = 1 + len(payload) + padding_length */
    f->pad_len = f->body[0];

    if(f->pad_len + 1 > f->pkt_len){
      f->st = SSH_S_FAIL; return SSHKEX_FAIL;
    }

    size_t payload_len = (size_t)(f->pkt_len - f->pad_len - 1);
    if(payload_len == 0){
      f->st = SSH_S_FAIL; return SSHKEX_FAIL;
    }

    const uint8_t *payload0 = f->body + 1;  /* skip padding_length byte */
    uint8_t msg_type = payload0[0];

    /* If not KEXINIT (type 20), skip this packet and look for the next one */
    if(msg_type != 20) {
      /* Reset to read next packet header */
      f->hdr_have = 0;
      f->st = SSH_S_KEX_HDR;
      return SSHKEX_IN_PROGRESS;
    }

    /* Found KEXINIT! Parse it */
    int is_pqc = 0; char alg[256] = {0};

    if(!kexinit_extract_kex(payload0, payload_len, alg, sizeof(alg), &is_pqc)){
      f->st = SSH_S_FAIL; return SSHKEX_FAIL;
    }

    /* latch chosen/first KEX name */
    strncpy(f->chosen_kex, alg, sizeof(f->chosen_kex)-1);
    if(out_alg) { strncpy(out_alg, alg, out_cap ? out_cap-1 : 0); if(out_cap) out_alg[out_cap-1] = '\0'; }

    f->st = SSH_S_DONE;
    return is_pqc ? SSHKEX_FOUND_PQC : SSHKEX_FOUND_NONPQC;
  }

  return SSHKEX_IN_PROGRESS;
}
