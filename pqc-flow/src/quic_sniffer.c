// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Copyright (c) 2025 Graziano Labs Corp.
 *
 * QUIC Protocol Sniffer Implementation
 */

#include "quic_sniffer.h"
#include <string.h>
#include <stdio.h>

/* Read 32-bit big-endian */
static inline uint32_t rd32(const uint8_t *p) {
    return (uint32_t)((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}

const char* quic_version_name(uint32_t version) {
    switch (version) {
        case QUIC_VERSION_1:            return "QUICv1";
        case QUIC_VERSION_2:            return "QUICv2";
        case QUIC_VERSION_NEGOTIATION:  return "QUIC-VN";
        default:
            /* Draft versions: 0xff0000XX */
            if ((version & 0xffffff00) == 0xff000000) {
                return "QUIC-draft";
            }
            return "QUIC-unknown";
    }
}

bool quic_is_likely(const uint8_t *data, size_t len) {
    if (len < 5) return false;

    uint8_t first = data[0];

    /* Check for long header: Header Form (bit 7) = 1, Fixed Bit (bit 6) = 1 */
    if ((first & 0xC0) == 0xC0) {
        /* Long header - check version field makes sense */
        uint32_t version = rd32(data + 1);

        /* Known versions or version negotiation */
        if (version == QUIC_VERSION_1 ||
            version == QUIC_VERSION_2 ||
            version == QUIC_VERSION_NEGOTIATION ||
            (version & 0xff000000) == 0xff000000) {  /* Draft versions */
            return true;
        }
    }

    /* Check for short header: Header Form (bit 7) = 0, Fixed Bit (bit 6) = 1 */
    if ((first & 0xC0) == 0x40) {
        /* Short header - harder to validate without connection state */
        /* For now, we only detect long headers (connection setup) */
        return false;
    }

    return false;
}

char* quic_format_cid(const uint8_t *cid, uint8_t cid_len, char *out, size_t out_cap) {
    if (!out || out_cap < 1) return NULL;

    size_t i;
    for (i = 0; i < cid_len && i * 2 + 2 < out_cap; i++) {
        snprintf(out + i * 2, 3, "%02x", cid[i]);
    }
    out[i * 2] = '\0';

    return out;
}

quic_rc quic_feed(quic_fsm *f, const uint8_t *payload, size_t plen) {
    /* Already done or failed */
    if (f->st == QUIC_S_DONE) return QUIC_DETECTED;
    if (f->st == QUIC_S_FAIL) return QUIC_FAIL;

    /* Need at least 5 bytes (first byte + version) */
    if (plen < 5) return QUIC_IN_PROGRESS;

    uint8_t first = payload[0];

    /* Check for long header format */
    if ((first & 0xC0) != 0xC0) {
        /* Short header or not QUIC - skip for now */
        /* We only process long headers during connection setup */
        return QUIC_IN_PROGRESS;
    }

    /* Parse long header */
    f->version = rd32(payload + 1);
    strncpy(f->version_str, quic_version_name(f->version), sizeof(f->version_str) - 1);

    /* Extract packet type from bits 4-5 */
    f->packet_type = (first >> 4) & 0x03;

    /* Version Negotiation packet (version = 0) has different format */
    if (f->version == QUIC_VERSION_NEGOTIATION) {
        f->st = QUIC_S_DONE;
        return QUIC_DETECTED;
    }

    /* Parse connection IDs */
    if (plen < 6) return QUIC_IN_PROGRESS;

    f->dcid_len = payload[5];
    if (f->dcid_len > QUIC_MAX_CID_LEN || plen < (size_t)(6 + f->dcid_len)) {
        f->st = QUIC_S_FAIL;
        return QUIC_FAIL;
    }

    memcpy(f->dcid, payload + 6, f->dcid_len);

    size_t scid_off = 6 + f->dcid_len;
    if (plen < scid_off + 1) return QUIC_IN_PROGRESS;

    f->scid_len = payload[scid_off];
    if (f->scid_len > QUIC_MAX_CID_LEN || plen < scid_off + 1 + (size_t)f->scid_len) {
        f->st = QUIC_S_FAIL;
        return QUIC_FAIL;
    }

    memcpy(f->scid, payload + scid_off + 1, f->scid_len);

    /* Update state based on packet type */
    switch (f->packet_type) {
        case QUIC_PKT_INITIAL:
            f->initial_seen = 1;
            if (f->st == QUIC_S_START) {
                f->st = QUIC_S_INITIAL;
            }
            break;

        case QUIC_PKT_HANDSHAKE:
            f->handshake_seen = 1;
            if (f->st == QUIC_S_INITIAL) {
                f->st = QUIC_S_HANDSHAKE;
            }
            break;

        case QUIC_PKT_0RTT:
            f->zero_rtt_seen = 1;
            break;

        case QUIC_PKT_RETRY:
            /* Retry packet - connection might restart */
            f->has_token = 1;
            break;
    }

    /* Consider detection complete after seeing Initial + Handshake or just Initial with response */
    if (f->initial_seen && f->handshake_seen) {
        f->st = QUIC_S_DONE;
        return QUIC_DETECTED;
    }

    /* Also consider done after seeing Initial from both directions */
    if (f->initial_seen) {
        /* For simplicity, report on first Initial packet */
        f->st = QUIC_S_DONE;
        return QUIC_DETECTED;
    }

    return QUIC_IN_PROGRESS;
}
