// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Copyright (c) 2025 Graziano Labs Corp.
 *
 * IKEv2 Key Exchange Sniffer
 * Parses IKEv2 SA_INIT exchanges to detect PQC key exchange algorithms.
 *
 * IKEv2 (RFC 7296) uses Diffie-Hellman groups for key exchange.
 * PQC groups are defined in RFC 9242 and IANA registry.
 */

#ifndef IKE_KEX_SNIFFER_H
#define IKE_KEX_SNIFFER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Return codes */
typedef enum {
    IKE_IN_PROGRESS = 0,    /* More data needed */
    IKE_FOUND_PQC   = 1,    /* PQC/hybrid algorithm detected */
    IKE_FOUND_NONPQC = 2,   /* Classical algorithm detected */
    IKE_FAIL        = -1    /* Parsing error */
} ike_rc;

/* FSM states */
typedef enum {
    IKE_S_START = 0,
    IKE_S_SA_INIT_REQ,      /* Saw SA_INIT request (initiator) */
    IKE_S_SA_INIT_RSP,      /* Saw SA_INIT response (responder) */
    IKE_S_DONE,
    IKE_S_FAIL
} ike_state_t;

/* IKEv2 Exchange Types */
#define IKE_EXCHANGE_SA_INIT    34
#define IKE_EXCHANGE_SA_AUTH    35
#define IKE_EXCHANGE_CREATE_CHILD 36
#define IKE_EXCHANGE_INFORMATIONAL 37

/* IKEv2 Payload Types */
#define IKE_PAYLOAD_SA          33  /* Security Association */
#define IKE_PAYLOAD_KE          34  /* Key Exchange */
#define IKE_PAYLOAD_NONCE       40  /* Nonce */

/* IKEv2 Transform Types */
#define IKE_TRANSFORM_ENCR      1   /* Encryption Algorithm */
#define IKE_TRANSFORM_PRF       2   /* Pseudo-Random Function */
#define IKE_TRANSFORM_INTEG     3   /* Integrity Algorithm */
#define IKE_TRANSFORM_DH        4   /* Diffie-Hellman Group */

/* Classical DH Group Numbers (IANA registry) */
#define IKE_DH_MODP_768         1   /* 768-bit MODP (weak) */
#define IKE_DH_MODP_1024        2   /* 1024-bit MODP (weak) */
#define IKE_DH_MODP_1536        5   /* 1536-bit MODP */
#define IKE_DH_MODP_2048        14  /* 2048-bit MODP */
#define IKE_DH_MODP_3072        15  /* 3072-bit MODP */
#define IKE_DH_MODP_4096        16  /* 4096-bit MODP */
#define IKE_DH_MODP_6144        17  /* 6144-bit MODP */
#define IKE_DH_MODP_8192        18  /* 8192-bit MODP */
#define IKE_DH_ECP_256          19  /* 256-bit ECP */
#define IKE_DH_ECP_384          20  /* 384-bit ECP */
#define IKE_DH_ECP_521          21  /* 521-bit ECP */
#define IKE_DH_MODP_1024_160    22  /* 1024-bit MODP with 160-bit POS */
#define IKE_DH_MODP_2048_224    23  /* 2048-bit MODP with 224-bit POS */
#define IKE_DH_MODP_2048_256    24  /* 2048-bit MODP with 256-bit POS */
#define IKE_DH_ECP_192          25  /* 192-bit Random ECP */
#define IKE_DH_ECP_224          26  /* 224-bit Random ECP */
#define IKE_DH_BRAINPOOL_224    27  /* brainpoolP224r1 */
#define IKE_DH_BRAINPOOL_256    28  /* brainpoolP256r1 */
#define IKE_DH_BRAINPOOL_384    29  /* brainpoolP384r1 */
#define IKE_DH_BRAINPOOL_512    30  /* brainpoolP512r1 */
#define IKE_DH_X25519           31  /* Curve25519 */
#define IKE_DH_X448             32  /* Curve448 */

/* PQC/Hybrid DH Group Numbers (RFC 9242 / IANA pending)
 * These are experimental/proposed values - check IANA for updates */
#define IKE_DH_ML_KEM_512       35  /* ML-KEM-512 (Kyber512) */
#define IKE_DH_ML_KEM_768       36  /* ML-KEM-768 (Kyber768) */
#define IKE_DH_ML_KEM_1024      37  /* ML-KEM-1024 (Kyber1024) */
#define IKE_DH_X25519_ML_KEM_768 38 /* X25519 + ML-KEM-768 hybrid */
#define IKE_DH_SNTRUP761        39  /* sntrup761 */
#define IKE_DH_X25519_SNTRUP761 40  /* X25519 + sntrup761 hybrid */

/* Per-flow FSM state */
typedef struct {
    ike_state_t st;

    /* IKEv2 header info */
    uint64_t initiator_spi;
    uint64_t responder_spi;
    uint8_t major_version;
    uint8_t minor_version;
    uint8_t exchange_type;
    uint8_t flags;
    uint32_t message_id;

    /* Key Exchange data */
    uint16_t ke_offered[16];        /* DH groups offered (initiator) */
    int ke_offered_count;
    uint16_t ke_selected;           /* DH group selected (responder) */
    char ke_group_name[64];         /* Human-readable group name */

    /* Transform data */
    char encr_alg[64];              /* Encryption algorithm */
    char prf_alg[64];               /* PRF algorithm */
    char integ_alg[64];             /* Integrity algorithm */

    /* PQC detection */
    uint8_t pqc_detected;
    uint8_t hybrid_detected;
    char pqc_algorithm[64];         /* PQC algorithm name if detected */
} ike_kex_fsm;

/**
 * Initialize IKE FSM.
 */
static inline void ike_kex_init(ike_kex_fsm *f) {
    *f = (ike_kex_fsm){ .st = IKE_S_START };
}

/**
 * Feed UDP payload bytes to IKE parser.
 *
 * @param f             FSM state
 * @param payload       UDP payload (after UDP header)
 * @param plen          Payload length
 * @param is_initiator  1 if from initiator (client), 0 if from responder
 * @return IKE_IN_PROGRESS, IKE_FOUND_PQC, IKE_FOUND_NONPQC, or IKE_FAIL
 */
ike_rc ike_kex_feed(ike_kex_fsm *f, const uint8_t *payload, size_t plen, int is_initiator);

/**
 * Get human-readable name for DH group number.
 *
 * @param group_num IANA DH group number
 * @return Group name string (static, do not free)
 */
const char* ike_dh_group_name(uint16_t group_num);

/**
 * Check if DH group is PQC-based.
 *
 * @param group_num IANA DH group number
 * @return true if PQC algorithm
 */
bool ike_dh_group_is_pqc(uint16_t group_num);

/**
 * Check if DH group is hybrid (classical + PQC).
 *
 * @param group_num IANA DH group number
 * @return true if hybrid algorithm
 */
bool ike_dh_group_is_hybrid(uint16_t group_num);

#endif /* IKE_KEX_SNIFFER_H */
