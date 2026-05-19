// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Copyright (c) 2025 Graziano Labs Corp.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Return codes */
typedef enum {
  TLSPQC_IN_PROGRESS = 0,
  TLSPQC_FOUND_PQC   = 1,   /* Negotiated group is PQC/hybrid */
  TLSPQC_FOUND_CLASSIC = 2, /* Classical groups only */
  TLSPQC_FAIL        = -1
} tlspqc_rc;

/* Internal FSM states */
typedef enum {
  TLS_S_START = 0,
  TLS_S_REC_HDR,      /* Reading TLS record header */
  TLS_S_HS_HDR,       /* Reading handshake message header */
  TLS_S_HS_BODY,      /* Reading handshake message body */
  TLS_S_DONE,
  TLS_S_FAIL
} tls_pqc_state;

/* TLS max record size (RFC 8446) */
#define TLS_MAX_RECORD_SIZE 16384

/* Per-flow TLS parser state (bounded memory) */
typedef struct {
  tls_pqc_state st;

  /* TLS record header: [type:1][version:2][length:2] */
  uint8_t rec_hdr[5];
  size_t rec_hdr_have;
  uint8_t rec_type;
  uint16_t rec_len;

  /* Handshake header: [msg_type:1][length:3] */
  uint8_t hs_hdr[4];
  size_t hs_hdr_have;
  uint8_t hs_type;
  uint32_t hs_len;

  /* Handshake body buffer (ClientHello/ServerHello/Certificate)
   * Sized to hold max TLS record (16KB) to capture certificate chains.
   * TLS 1.2 certificates are sent in plaintext and can be large. */
  uint8_t body[TLS_MAX_RECORD_SIZE];
  size_t body_have, body_need;

  /* Extracted data */
  char negotiated_group[64];
  char server_name[256];         /* SNI from ClientHello */
  char cipher_suite[64];         /* Selected cipher from ServerHello */
  uint16_t cipher_id;            /* Cipher suite ID */
  uint16_t offered_version;      /* TLS version from ClientHello */
  uint16_t negotiated_version;   /* TLS version from ServerHello */
  uint8_t seen_client_hello:1;
  uint8_t seen_server_hello:1;
  uint8_t seen_certificate:1;
  bool exported;

  /* Certificate data (from Certificate message) */
  char cert_fingerprint[65];     /* SHA256 hex (64 chars + null) */
  char cert_subject[256];        /* Leaf certificate subject */
  char cert_issuer[256];         /* Leaf certificate issuer */
} tls_pqc_fsm;

static inline void tls_pqc_init(tls_pqc_fsm *f) {
  *f = (tls_pqc_fsm){ .st = TLS_S_START };
}

/**
 * Feed TCP payload bytes from TLS connection.
 * @param payload   TCP payload (TLS records)
 * @param plen      Payload length
 * @param out_group Output buffer for negotiated group name
 * @param out_cap   Output buffer capacity
 * @return TLSPQC_* status code
 */
tlspqc_rc tls_pqc_feed(tls_pqc_fsm *f,
                       const uint8_t *payload, size_t plen,
                       char *out_group, size_t out_cap);
