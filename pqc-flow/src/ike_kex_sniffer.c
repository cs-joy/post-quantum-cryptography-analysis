// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Copyright (c) 2025 Graziano Labs Corp.
 *
 * IKEv2 Key Exchange Sniffer Implementation
 */

#include "ike_kex_sniffer.h"
#include <string.h>
#include <arpa/inet.h>

/* IKEv2 Header size */
#define IKE_HDR_LEN 28

/* IKEv2 Generic Payload Header */
#define IKE_PAYLOAD_HDR_LEN 4

/* IKEv2 Flags */
#define IKE_FLAG_INITIATOR  0x08
#define IKE_FLAG_VERSION    0x10
#define IKE_FLAG_RESPONSE   0x20

/* Read 16-bit big-endian */
static inline uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

/* Read 32-bit big-endian */
static inline uint32_t rd32(const uint8_t *p) {
    return (uint32_t)((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}

/* Read 64-bit big-endian */
static inline uint64_t rd64(const uint8_t *p) {
    return ((uint64_t)rd32(p) << 32) | rd32(p + 4);
}

const char* ike_dh_group_name(uint16_t group_num) {
    switch(group_num) {
        case 1:  return "MODP-768";
        case 2:  return "MODP-1024";
        case 5:  return "MODP-1536";
        case 14: return "MODP-2048";
        case 15: return "MODP-3072";
        case 16: return "MODP-4096";
        case 17: return "MODP-6144";
        case 18: return "MODP-8192";
        case 19: return "ECP-256";
        case 20: return "ECP-384";
        case 21: return "ECP-521";
        case 22: return "MODP-1024-160";
        case 23: return "MODP-2048-224";
        case 24: return "MODP-2048-256";
        case 25: return "ECP-192";
        case 26: return "ECP-224";
        case 27: return "brainpoolP224r1";
        case 28: return "brainpoolP256r1";
        case 29: return "brainpoolP384r1";
        case 30: return "brainpoolP512r1";
        case 31: return "X25519";
        case 32: return "X448";
        /* PQC groups (experimental/proposed) */
        case 35: return "ML-KEM-512";
        case 36: return "ML-KEM-768";
        case 37: return "ML-KEM-1024";
        case 38: return "X25519-ML-KEM-768";
        case 39: return "sntrup761";
        case 40: return "X25519-sntrup761";
        default: return "UNKNOWN";
    }
}

bool ike_dh_group_is_pqc(uint16_t group_num) {
    /* PQC groups: ML-KEM variants and sntrup */
    return (group_num >= 35 && group_num <= 40);
}

bool ike_dh_group_is_hybrid(uint16_t group_num) {
    /* Hybrid groups combine classical + PQC */
    return (group_num == 38 || group_num == 40);  /* X25519+ML-KEM, X25519+sntrup */
}

/* Parse IKEv2 SA payload to extract DH groups from transforms */
static int parse_sa_payload(const uint8_t *data, size_t len, ike_kex_fsm *f) {
    size_t off = 0;

    /* SA payload contains one or more Proposals */
    while (off + 8 <= len) {
        /* Proposal substructure header:
         * 0: Last Substruc (0=more, 2=last)
         * 1: Reserved
         * 2-3: Proposal Length
         * 4: Proposal Num
         * 5: Protocol ID (1=IKE, 2=AH, 3=ESP)
         * 6: SPI Size
         * 7: Num Transforms
         */
        uint16_t prop_len = rd16(data + off + 2);
        uint8_t num_transforms = data[off + 7];
        uint8_t spi_size = data[off + 6];

        if (prop_len == 0 || off + prop_len > len) break;

        /* Skip to transforms (after SPI) */
        size_t trans_off = off + 8 + spi_size;

        for (int t = 0; t < num_transforms && trans_off + 8 <= off + prop_len; t++) {
            /* Transform substructure:
             * 0: Last Substruc (0=more, 3=last)
             * 1: Reserved
             * 2-3: Transform Length
             * 4: Transform Type
             * 5: Reserved
             * 6-7: Transform ID
             */
            uint16_t trans_len = rd16(data + trans_off + 2);
            uint8_t trans_type = data[trans_off + 4];
            uint16_t trans_id = rd16(data + trans_off + 6);

            if (trans_len == 0 || trans_off + trans_len > off + prop_len) break;

            /* Extract DH group (Transform Type 4) */
            if (trans_type == IKE_TRANSFORM_DH) {
                /* Add to offered list */
                if (f->ke_offered_count < 16) {
                    f->ke_offered[f->ke_offered_count++] = trans_id;
                }

                /* Check for PQC */
                if (ike_dh_group_is_pqc(trans_id)) {
                    f->pqc_detected = 1;
                    if (ike_dh_group_is_hybrid(trans_id)) {
                        f->hybrid_detected = 1;
                    }
                    strncpy(f->pqc_algorithm, ike_dh_group_name(trans_id),
                            sizeof(f->pqc_algorithm) - 1);
                }
            }

            trans_off += trans_len;
        }

        off += prop_len;
    }

    return f->ke_offered_count > 0 ? 1 : 0;
}

/* Parse IKEv2 KE payload to extract the selected DH group */
static int parse_ke_payload(const uint8_t *data, size_t len, ike_kex_fsm *f) {
    if (len < 4) return 0;

    /* KE payload:
     * 0-1: DH Group Num
     * 2-3: Reserved
     * 4+: Key Exchange Data
     */
    f->ke_selected = rd16(data);
    strncpy(f->ke_group_name, ike_dh_group_name(f->ke_selected),
            sizeof(f->ke_group_name) - 1);

    if (ike_dh_group_is_pqc(f->ke_selected)) {
        f->pqc_detected = 1;
        if (ike_dh_group_is_hybrid(f->ke_selected)) {
            f->hybrid_detected = 1;
        }
        strncpy(f->pqc_algorithm, f->ke_group_name, sizeof(f->pqc_algorithm) - 1);
    }

    return 1;
}

ike_rc ike_kex_feed(ike_kex_fsm *f, const uint8_t *payload, size_t plen, int is_initiator) {
    (void)is_initiator;  /* Direction determined from IKE header flags */

    /* Already done or failed */
    if (f->st == IKE_S_DONE) return f->pqc_detected ? IKE_FOUND_PQC : IKE_FOUND_NONPQC;
    if (f->st == IKE_S_FAIL) return IKE_FAIL;

    /* Need at least IKE header */
    if (plen < IKE_HDR_LEN) return IKE_IN_PROGRESS;

    /* Parse IKEv2 header */
    f->initiator_spi = rd64(payload);
    f->responder_spi = rd64(payload + 8);

    uint8_t next_payload = payload[16];
    uint8_t version = payload[17];
    f->major_version = (version >> 4) & 0x0F;
    f->minor_version = version & 0x0F;
    f->exchange_type = payload[18];
    f->flags = payload[19];
    f->message_id = rd32(payload + 20);
    uint32_t total_len = rd32(payload + 24);

    /* Validate */
    if (f->major_version != 2) {
        /* Not IKEv2 */
        f->st = IKE_S_FAIL;
        return IKE_FAIL;
    }

    if (total_len > plen || total_len < IKE_HDR_LEN) {
        return IKE_IN_PROGRESS;  /* Fragmented */
    }

    /* Only process SA_INIT exchanges */
    if (f->exchange_type != IKE_EXCHANGE_SA_INIT) {
        return IKE_IN_PROGRESS;  /* Skip non-SA_INIT */
    }

    /* Parse payloads */
    size_t off = IKE_HDR_LEN;
    int found_sa = 0;
    int found_ke = 0;

    while (next_payload != 0 && off + IKE_PAYLOAD_HDR_LEN <= total_len) {
        uint8_t curr_payload = next_payload;
        next_payload = payload[off];
        /* uint8_t critical = payload[off + 1]; */
        uint16_t payload_len = rd16(payload + off + 2);

        if (payload_len < IKE_PAYLOAD_HDR_LEN || off + payload_len > total_len) {
            break;  /* Invalid payload */
        }

        const uint8_t *payload_data = payload + off + IKE_PAYLOAD_HDR_LEN;
        size_t data_len = payload_len - IKE_PAYLOAD_HDR_LEN;

        switch (curr_payload) {
            case IKE_PAYLOAD_SA:
                found_sa = parse_sa_payload(payload_data, data_len, f);
                break;

            case IKE_PAYLOAD_KE:
                found_ke = parse_ke_payload(payload_data, data_len, f);
                break;
        }

        off += payload_len;
    }

    /* Update state based on what we found */
    int is_response = (f->flags & IKE_FLAG_RESPONSE) != 0;

    if (!is_response && found_sa) {
        /* SA_INIT request with SA payload */
        f->st = IKE_S_SA_INIT_REQ;
    } else if (is_response && found_ke) {
        /* SA_INIT response with KE payload */
        f->st = IKE_S_SA_INIT_RSP;
    }

    /* Done if we've seen both request and response, or just the response */
    if (f->st == IKE_S_SA_INIT_RSP) {
        f->st = IKE_S_DONE;
        return f->pqc_detected ? IKE_FOUND_PQC : IKE_FOUND_NONPQC;
    }

    return IKE_IN_PROGRESS;
}
