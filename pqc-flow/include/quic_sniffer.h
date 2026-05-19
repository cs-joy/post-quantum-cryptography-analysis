// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Copyright (c) 2025 Graziano Labs Corp.
 *
 * QUIC Protocol Sniffer
 *
 * Detects QUIC connections and extracts version/connection info.
 * Note: QUIC Initial packets are encrypted, so TLS ClientHello extraction
 * requires decryption with Initial secrets derived from DCID. This implementation
 * focuses on detecting QUIC and extracting visible metadata.
 *
 * QUIC Versions:
 * - RFC 9000 QUIC v1: 0x00000001
 * - RFC 9369 QUIC v2: 0x6b3343cf
 * - Version Negotiation: 0x00000000 (indicates version negotiation)
 *
 * PQC Relevance:
 * - QUIC mandates TLS 1.3, which supports PQC key exchange
 * - Same PQC groups as TLS (X25519Kyber768, etc.)
 * - HTTP/3 uses QUIC, making it increasingly common
 */

#ifndef QUIC_SNIFFER_H
#define QUIC_SNIFFER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Return codes */
typedef enum {
    QUIC_IN_PROGRESS = 0,   /* More data needed */
    QUIC_DETECTED    = 1,   /* QUIC connection detected */
    QUIC_FAIL        = -1   /* Not QUIC or parsing error */
} quic_rc;

/* FSM states */
typedef enum {
    QUIC_S_START = 0,
    QUIC_S_INITIAL,         /* Saw Initial packet */
    QUIC_S_HANDSHAKE,       /* Saw Handshake packet */
    QUIC_S_DONE,
    QUIC_S_FAIL
} quic_state_t;

/* QUIC packet types (long header) */
#define QUIC_PKT_INITIAL    0x00
#define QUIC_PKT_0RTT       0x01
#define QUIC_PKT_HANDSHAKE  0x02
#define QUIC_PKT_RETRY      0x03

/* Known QUIC versions */
#define QUIC_VERSION_1          0x00000001  /* RFC 9000 */
#define QUIC_VERSION_2          0x6b3343cf  /* RFC 9369 */
#define QUIC_VERSION_NEGOTIATION 0x00000000

/* Maximum connection ID length */
#define QUIC_MAX_CID_LEN 20

/* Per-flow FSM state */
typedef struct {
    quic_state_t st;

    /* QUIC version */
    uint32_t version;
    char version_str[32];

    /* Connection IDs */
    uint8_t dcid[QUIC_MAX_CID_LEN];
    uint8_t dcid_len;
    uint8_t scid[QUIC_MAX_CID_LEN];
    uint8_t scid_len;

    /* Packet type */
    uint8_t packet_type;

    /* Token (from Retry packet or server address validation) */
    uint8_t has_token;
    uint16_t token_len;

    /* ALPN (if detected, e.g., from nDPI) */
    char alpn[32];          /* e.g., "h3", "h3-29" */

    /* Detection flags */
    uint8_t initial_seen;
    uint8_t handshake_seen;
    uint8_t zero_rtt_seen;

    /* Note: PQC detection in QUIC requires decrypting the Initial packet
     * to access the TLS ClientHello. This is not implemented here.
     * Use nDPI's QUIC detection for TLS info extraction. */
} quic_fsm;

/**
 * Initialize QUIC FSM.
 */
static inline void quic_init(quic_fsm *f) {
    *f = (quic_fsm){ .st = QUIC_S_START };
}

/**
 * Feed UDP payload bytes to QUIC parser.
 *
 * Detects QUIC long headers and extracts version/connection IDs.
 *
 * @param f        FSM state
 * @param payload  UDP payload (after UDP header)
 * @param plen     Payload length
 * @return QUIC_DETECTED if QUIC packet identified, QUIC_IN_PROGRESS to continue,
 *         QUIC_FAIL if not QUIC
 */
quic_rc quic_feed(quic_fsm *f, const uint8_t *payload, size_t plen);

/**
 * Get human-readable name for QUIC version.
 *
 * @param version QUIC version number
 * @return Version name string (static, do not free)
 */
const char* quic_version_name(uint32_t version);

/**
 * Check if this looks like a QUIC packet.
 *
 * Quick check for QUIC long header format:
 * - First byte has fixed bit (0x40)
 * - Version field is non-zero (or zero for version negotiation)
 *
 * @param data  UDP payload
 * @param len   Payload length
 * @return true if likely QUIC, false otherwise
 */
bool quic_is_likely(const uint8_t *data, size_t len);

/**
 * Format connection ID as hex string.
 *
 * @param cid     Connection ID bytes
 * @param cid_len Connection ID length
 * @param out     Output buffer (must be at least 2*cid_len + 1)
 * @param out_cap Output buffer capacity
 * @return Pointer to out buffer
 */
char* quic_format_cid(const uint8_t *cid, uint8_t cid_len, char *out, size_t out_cap);

#endif /* QUIC_SNIFFER_H */
