// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Copyright (c) 2025 Graziano Labs Corp.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "pqc_detect.h"

static void reset_meta(FlowMeta *m) {
  memset(m, 0, sizeof(*m));
}

int main(void) {
  FlowMeta m;
  reset_meta(&m);

  // Test 1: TLS hybrid negotiated
  strcpy(m.tls_supported_groups, "x25519, ml-kem-768");
  strcpy(m.tls_negotiated_group, "X25519+ML-KEM-768");
  pqc_from_strings(&m, "tls", m.tls_supported_groups, m.tls_negotiated_group, m.tls_sig_algs, m.tls_server_sigalg);
  assert((m.pqc_flags & (PQC_KEM_PRESENT|HYBRID_NEGOTIATED)) == (PQC_KEM_PRESENT|HYBRID_NEGOTIATED));

  // Test 2: SSH sntrup hybrid
  reset_meta(&m);
  strcpy(m.ssh_kex_negotiated, "sntrup761x25519-sha512@openssh.com");
  pqc_from_strings(&m, "ssh", m.ssh_kex_offered, m.ssh_kex_negotiated, m.ssh_hostkey_offered, m.ssh_sig_alg);
  assert((m.pqc_flags & (PQC_KEM_PRESENT|HYBRID_NEGOTIATED)) == (PQC_KEM_PRESENT|HYBRID_NEGOTIATED));

  // Test 3: Signature PQC offered and used
  reset_meta(&m);
  strcpy(m.tls_sig_algs, "rsa_pss_rsae_sha256, ml-dsa-87");
  strcpy(m.tls_server_sigalg, "ml-dsa-87");
  pqc_from_strings(&m, "tls", m.tls_supported_groups, m.tls_negotiated_group, m.tls_sig_algs, m.tls_server_sigalg);
  assert((m.pqc_flags & (PQC_SIG_PRESENT|PQC_CERT_OR_HOSTKEY)) == (PQC_SIG_PRESENT|PQC_CERT_OR_HOSTKEY));

  printf("All PQC detection tests passed.\\n");
  return 0;
}