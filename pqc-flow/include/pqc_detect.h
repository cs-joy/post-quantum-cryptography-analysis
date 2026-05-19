// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Copyright (c) 2025 Graziano Labs Corp.
 */

#ifndef PQC_DETECT_H
#define PQC_DETECT_H

#include <stdint.h>
#include <stddef.h>

// PQC flags bitmask (general categories)
enum {
  PQC_KEM_PRESENT          = 1 << 0, // offered or chosen kem/kex includes PQC
  PQC_SIG_PRESENT          = 1 << 1, // signatures/hostkeys include PQC
  HYBRID_NEGOTIATED        = 1 << 2, // chosen kex is hybrid (classical + PQC)
  PQC_OFFERED_ONLY         = 1 << 3, // seen only in offers
  PQC_CERT_OR_HOSTKEY      = 1 << 4, // certificate or hostkey uses PQC/hybrid
  RESUMPTION_NO_HANDSHAKE  = 1 << 5  // resumed/abbreviated session
};

// Protocol-specific flag aliases (for clarity in code)
#define PQC_F_SSH_KEX    PQC_KEM_PRESENT
#define PQC_F_TLS_GROUP  PQC_KEM_PRESENT
#define PQC_F_IKE_KE     PQC_KEM_PRESENT
#define PQC_F_QUIC_TLS   PQC_KEM_PRESENT

// Flow metadata container (trimmed for starter)
typedef struct {
  // generic
  uint8_t pqc_flags;
  char pqc_reason[128];

  // TLS/DTLS
  char tls_supported_groups[256];
  char tls_keyshare_groups[128];
  char tls_negotiated_group[128];
  char tls_sig_algs[128];
  char tls_server_sigalg[128];
  char tls_server_name[256];           // SNI from ClientHello
  char tls_cipher_suite[64];           // Negotiated cipher suite
  char tls_cert_fingerprint[65];       // SHA256 fingerprint of leaf cert (hex)
  char tls_cert_subject[256];          // Leaf certificate subject
  char tls_cert_issuer[256];           // Leaf certificate issuer

  // SSH
  char ssh_kex_offered[256];
  char ssh_kex_negotiated[256];
  char ssh_hostkey_offered[256];
  char ssh_hostkey_negotiated[128];
  char ssh_sig_alg[128];
  char ssh_cipher[96];                   // Negotiated encryption cipher
  char ssh_mac[96];                      // Negotiated MAC algorithm

  // IKEv2
  char ike_ke_offered[128];
  char ike_ke_chosen[64];
  char ike_vendor_ids[128];

  // QUIC
  char quic_tls_supported_groups[256];
  char quic_tls_keyshare_groups[128];
  char quic_tls_negotiated_group[128];
  char quic_tls_sig_algs[128];

  // WireGuard
  uint8_t wg_pqc_flags;
} FlowMeta;

// Simple helpers
int contains_token_ci(const char *hay, const char *tok);
void pqc_mark_reason(char *reason, size_t cap, const char *proto, const char *tok);

// Core detection function using strings already extracted from nDPI
void pqc_from_strings(FlowMeta *f, const char *proto,
                      const char *offered, const char *chosen,
                      const char *sig_offered, const char *sig_used);

#endif