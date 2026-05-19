// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Copyright (c) 2025 Graziano Labs Corp.
 */

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "pqc_detect.h"

static const char *KEM_TOKENS[] = {
  "ml-kem","kyber","sntrup","ntru","ntruprime","bike","hqc","frodo","+","hybrid"
};
static const char *SIG_TOKENS[] = {
  "ml-dsa","dilithium","slh-dsa","sphincs","falcon"
};

int contains_token_ci(const char *hay, const char *tok) {
  if(!hay || !tok) return 0;
  size_t n = strlen(hay), m = strlen(tok);
  if(m==0 || n<m) return 0;
  for(size_t i=0;i+ m<=n;i++){
    size_t j=0;
    for(; j<m; j++){
      char a = hay[i+j], b = tok[j];
      if(a>='A' && a<='Z') a = (char)(a-'A'+'a');
      if(b>='A' && b<='Z') b = (char)(b-'A'+'a');
      if(a!=b) break;
    }
    if(j==m) return 1;
  }
  return 0;
}

static void append_reason_once(char *dst, size_t cap, const char *tag) {
  if(!dst || !tag) return;
  if(strstr(dst, tag)) return; /* already present */
  size_t have = strlen(dst), need = strlen(tag);
  if(have + need >= cap) return;
  memcpy(dst + have, tag, need);
  dst[have + need] = '\0';
}

void pqc_mark_reason(char *reason, size_t cap, const char *proto, const char *tok) {
  if(!reason || !proto || !tok) return;
  char tag[128];
  int n = snprintf(tag, sizeof(tag), "%s:%s|", proto, tok);
  if(n > 0 && (size_t)n < sizeof(tag)) {
    append_reason_once(reason, cap, tag);
  }
}

void pqc_from_strings(FlowMeta *f, const char *proto,
                      const char *offered, const char *chosen,
                      const char *sig_offered, const char *sig_used) {
  if(!f) return;
  // offers
  for(size_t i=0;i<sizeof(KEM_TOKENS)/sizeof(*KEM_TOKENS);++i) {
    if(contains_token_ci(offered, KEM_TOKENS[i])) {
      f->pqc_flags |= PQC_KEM_PRESENT | PQC_OFFERED_ONLY;
      pqc_mark_reason(f->pqc_reason, sizeof(f->pqc_reason), proto, KEM_TOKENS[i]);
    }
  }
  // chosen
  for(size_t i=0;i<sizeof(KEM_TOKENS)/sizeof(*KEM_TOKENS);++i) {
    if(contains_token_ci(chosen, KEM_TOKENS[i])) {
      f->pqc_flags |= PQC_KEM_PRESENT;
      // Hybrid heuristics:
      // 1. Contains '+' (e.g., "X25519+ML-KEM-768")
      // 2. Contains "hybrid"
      // 3. Contains classical names alongside PQC (e.g., "sntrup761x25519" has both)
      if((chosen && strchr(chosen,'+')) ||
         contains_token_ci(chosen,"hybrid") ||
         (contains_token_ci(chosen,"sntrup") && contains_token_ci(chosen,"25519")) ||
         (contains_token_ci(chosen,"kyber") && contains_token_ci(chosen,"25519")) ||
         (contains_token_ci(chosen,"mlkem") && contains_token_ci(chosen,"25519")))
        f->pqc_flags |= HYBRID_NEGOTIATED;
      f->pqc_flags &= ~PQC_OFFERED_ONLY;
      pqc_mark_reason(f->pqc_reason, sizeof(f->pqc_reason), proto, KEM_TOKENS[i]);
    }
  }
  // signatures / hostkeys
  for(size_t i=0;i<sizeof(SIG_TOKENS)/sizeof(*SIG_TOKENS);++i) {
    if(contains_token_ci(sig_offered, SIG_TOKENS[i])) {
      f->pqc_flags |= PQC_SIG_PRESENT;
      pqc_mark_reason(f->pqc_reason, sizeof(f->pqc_reason), proto, SIG_TOKENS[i]);
    }
    if(contains_token_ci(sig_used, SIG_TOKENS[i])) {
      f->pqc_flags |= PQC_SIG_PRESENT | PQC_CERT_OR_HOSTKEY;
      pqc_mark_reason(f->pqc_reason, sizeof(f->pqc_reason), proto, SIG_TOKENS[i]);
    }
  }
}