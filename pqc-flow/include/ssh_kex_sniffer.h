// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Copyright (c) 2025 Graziano Labs Corp.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Return codes for one feed step */
typedef enum {
  SSHKEX_IN_PROGRESS = 0,
  SSHKEX_FOUND_PQC   = 1,   /* out_alg filled, matches PQC/hybrid */
  SSHKEX_FOUND_NONPQC= 2,   /* out_alg filled, but not PQC */
  SSHKEX_FAIL        = -1
} sshkex_rc;

/* Internal FSM states */
typedef enum {
  SSH_S_START = 0,
  SSH_S_VERS_CL,
  SSH_S_VERS_SRV,
  SSH_S_KEX_HDR,
  SSH_S_KEX_PAY,
  SSH_S_DONE,
  SSH_S_FAIL
} ssh_kex_state;

/* Per-flow, short-lived, bounded memory */
typedef struct {
  ssh_kex_state st;

  /* Version lines (ASCII, up to 127 + NUL) */
  char   v_cl[128]; size_t v_cl_len; bool cl_done;
  char   v_sv[128]; size_t v_sv_len; bool sv_done;

  /* First binary packet (KEXINIT) header & payload */
  uint8_t hdr[5];   size_t hdr_have;    /* [0..3]=packet_length, [4]=padding_length */
  uint32_t pkt_len; uint8_t pad_len;    /* computed after hdr complete */
  size_t  need_body;                    /* total bytes to read (packet_length) */
  size_t  got_body;                     /* body bytes accumulated so far */

  /* Body cap: few KB is plenty; KEXINIT is small */
  uint8_t body[2048];

  /* Latch the chosen algorithm once found */
  char chosen_kex[256];
  bool exported;
} ssh_kex_fsm;

static inline void ssh_kex_init(ssh_kex_fsm *f) {
  *f = (ssh_kex_fsm){ .st = SSH_S_START };
}

/**
 * Feed TCP payload bytes.
 * @param from_client  1 if this segment originates from the TCP peer using an ephemeral (>1024) port; 0 if from server (port 22).
 * @param out_alg      On FOUND_* returns, holds the chosen (or first) KEX name; null-terminated.
 */
sshkex_rc ssh_kex_feed(ssh_kex_fsm *f,
                       const uint8_t *payload, size_t plen,
                       int from_client,
                       char *out_alg, size_t out_cap);

/**
 * Extract specific algorithm types from KEXINIT payload (SSH_MSG_KEXINIT message).
 * These functions can be called after ssh_kex_feed returns FOUND_* and the body is available.
 * @param p    Pointer to KEXINIT payload (starting at message type byte 0x14)
 * @param n    Length of payload
 * @param out  Output buffer for algorithm name
 * @param cap  Capacity of output buffer
 * @return 1 on success, 0 on failure
 */
int kexinit_extract_hostkey(const uint8_t *p, size_t n, char *out, size_t cap);
int kexinit_extract_cipher(const uint8_t *p, size_t n, char *out, size_t cap);
int kexinit_extract_mac(const uint8_t *p, size_t n, char *out, size_t cap);
