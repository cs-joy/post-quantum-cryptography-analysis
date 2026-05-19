// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Copyright (c) 2025 Graziano Labs Corp.
 */

#define _GNU_SOURCE
#include "tls_pqc_sniffer.h"
#include <string.h>
#include <stdio.h>

/* For SHA256 fingerprint */
#include <openssl/sha.h>
#include <openssl/x509.h>

/* TLS constants */
#define TLS_RECORD_HANDSHAKE 0x16
#define TLS_HS_CLIENT_HELLO  0x01
#define TLS_HS_SERVER_HELLO  0x02
#define TLS_HS_CERTIFICATE   0x0b
#define TLS_EXT_SERVER_NAME        0x0000
#define TLS_EXT_SUPPORTED_GROUPS   0x000a
#define TLS_EXT_SUPPORTED_VERSIONS 0x002b
#define TLS_EXT_KEY_SHARE          0x0033

/* Utility functions */
static inline uint16_t be16(const uint8_t *p) {
  return ((uint16_t)p[0] << 8) | p[1];
}

static inline uint32_t be24(const uint8_t *p) {
  return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

/* Map TLS named group ID to string */
static const char* group_id_to_name(uint16_t id) {
  switch(id) {
    /* Classical ECDH */
    case 23: return "secp256r1";
    case 24: return "secp384r1";
    case 25: return "secp521r1";
    case 29: return "x25519";
    case 30: return "x448";

    /* FFDHE */
    case 256: return "ffdhe2048";
    case 257: return "ffdhe3072";
    case 258: return "ffdhe4096";
    case 259: return "ffdhe6144";
    case 260: return "ffdhe8192";

    /* Hybrid PQC - Kyber (pre-standard, Cloudflare/Google/Chrome) */
    case 0xfe30: return "X25519Kyber512Draft00";
    case 0xfe31: return "X25519Kyber768Draft00";
    case 0x6399: return "X25519Kyber768Draft00"; /* Alternate code */
    case 0x11ec: return "X25519Kyber768"; /* Chrome experimental */
    case 0x11ed: return "X25519Kyber1024"; /* Chrome experimental */

    /* ML-KEM (NIST standard drafts) */
    case 0x2001: return "X25519+ML-KEM-768";
    case 0x2002: return "X25519+ML-KEM-1024";
    case 0x2003: return "X448+ML-KEM-768";
    case 0x2004: return "X448+ML-KEM-1024";
    case 0x2005: return "P-256+ML-KEM-768";
    case 0x2006: return "P-384+ML-KEM-1024";
    case 0x2007: return "Brainpool256+ML-KEM-768";

    default:
      return NULL;  /* Unknown or not tracked */
  }
}

/* Check if group ID is PQC/hybrid */
static int is_pqc_group(uint16_t id) {
  /* Kyber hybrids */
  if(id >= 0xfe30 && id <= 0xfe37) return 1;
  if(id == 0x6399 || id == 0x639a) return 1; /* Cloudflare Kyber */
  if(id == 0x11ec || id == 0x11ed) return 1; /* Chrome Kyber experiment (TLS 1.3 code) */
  if(id == 0xdada) return 0; /* GREASE - not real PQC */

  /* ML-KEM hybrids (0x2000 range) */
  if(id >= 0x2001 && id <= 0x2010) return 1;

  return 0;
}

/* Map TLS cipher suite ID to string */
static const char* cipher_id_to_name(uint16_t id) {
  switch(id) {
    /* TLS 1.3 cipher suites */
    case 0x1301: return "TLS_AES_128_GCM_SHA256";
    case 0x1302: return "TLS_AES_256_GCM_SHA384";
    case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
    case 0x1304: return "TLS_AES_128_CCM_SHA256";
    case 0x1305: return "TLS_AES_128_CCM_8_SHA256";

    /* TLS 1.2 ECDHE-RSA */
    case 0xc02f: return "ECDHE-RSA-AES128-GCM-SHA256";
    case 0xc030: return "ECDHE-RSA-AES256-GCM-SHA384";
    case 0xc013: return "ECDHE-RSA-AES128-SHA";
    case 0xc014: return "ECDHE-RSA-AES256-SHA";
    case 0xcca8: return "ECDHE-RSA-CHACHA20-POLY1305";

    /* TLS 1.2 ECDHE-ECDSA */
    case 0xc02b: return "ECDHE-ECDSA-AES128-GCM-SHA256";
    case 0xc02c: return "ECDHE-ECDSA-AES256-GCM-SHA384";
    case 0xc009: return "ECDHE-ECDSA-AES128-SHA";
    case 0xc00a: return "ECDHE-ECDSA-AES256-SHA";
    case 0xcca9: return "ECDHE-ECDSA-CHACHA20-POLY1305";

    /* TLS 1.2 DHE-RSA */
    case 0x009e: return "DHE-RSA-AES128-GCM-SHA256";
    case 0x009f: return "DHE-RSA-AES256-GCM-SHA384";

    /* TLS 1.2 RSA (no PFS) */
    case 0x009c: return "AES128-GCM-SHA256";
    case 0x009d: return "AES256-GCM-SHA384";
    case 0x002f: return "AES128-SHA";
    case 0x0035: return "AES256-SHA";

    default: return NULL;
  }
}

/* Parse extensions to find supported_groups, key_share, SNI, and supported_versions */
static int parse_extensions(const uint8_t *exts, size_t exts_len,
                           uint16_t *out_negotiated, char *out_name, size_t out_cap,
                           char *out_sni, size_t sni_cap,
                           int is_server_hello, uint16_t *out_version) {
  size_t off = 0;
  int found_any = 0;

  while(off + 4 <= exts_len) {
    uint16_t ext_type = be16(exts + off);
    uint16_t ext_len = be16(exts + off + 2);
    off += 4;

    if(off + ext_len > exts_len) break;

    /* Server Name Indication (SNI) - extension type 0x0000 */
    if(ext_type == TLS_EXT_SERVER_NAME && ext_len >= 5 && out_sni) {
      /* server_name_list = [list_len:2][name_type:1][name_len:2][name] */
      uint16_t list_len = be16(exts + off);
      if(2 + list_len <= ext_len && list_len >= 3) {
        uint8_t name_type = exts[off + 2];
        uint16_t name_len = be16(exts + off + 3);
        if(name_type == 0 && 5 + name_len <= ext_len) { /* host_name type */
          size_t copy_len = (name_len < sni_cap - 1) ? name_len : sni_cap - 1;
          memcpy(out_sni, exts + off + 5, copy_len);
          out_sni[copy_len] = '\0';
        }
      }
    }

    if(ext_type == TLS_EXT_SUPPORTED_GROUPS && ext_len >= 2) {
      /* supported_groups = [length:2][group_list] */
      uint16_t list_len = be16(exts + off);

      if(2 + list_len <= ext_len) {
        /* Walk group list */
        for(size_t i = 0; i < list_len; i += 2) {
          if(2 + i + 2 > ext_len) break;
          uint16_t gid = be16(exts + off + 2 + i);

          if(is_pqc_group(gid)) {
            const char *name = group_id_to_name(gid);
            if(name && out_name) {
              strncpy(out_name, name, out_cap - 1);
              out_name[out_cap - 1] = '\0';
            }
            if(out_negotiated) *out_negotiated = gid;
            found_any = 1;
            break; /* Use first PQC group found */
          }
        }
      }
    } else if(ext_type == TLS_EXT_KEY_SHARE) {
      /* ServerHello key_share = [group:2][key_exchange_len:2][key_exchange] */
      /* ClientHello key_share = [client_shares_len:2][entries...] */
      if(ext_len >= 2) {
        uint16_t gid = be16(exts + off);
        /* Check if first 2 bytes look like a group ID (not a length) */
        if(gid < 0x0100 || gid >= 0x2000) {
          /* Likely ServerHello format: direct group ID */
          const char *name = group_id_to_name(gid);
          if(name && out_name) {
            strncpy(out_name, name, out_cap - 1);
            out_name[out_cap - 1] = '\0';
          }
          if(out_negotiated) *out_negotiated = gid;
          found_any = 1;
        }
      }
    }

    /* supported_versions extension (0x002b) - TLS 1.3 actual version */
    if(ext_type == TLS_EXT_SUPPORTED_VERSIONS && out_version) {
      if(is_server_hello) {
        /* ServerHello: [selected_version:2] */
        if(ext_len >= 2) {
          *out_version = be16(exts + off);
        }
      } else {
        /* ClientHello: [length:1][version_list] - take first (highest) */
        if(ext_len >= 3) {
          uint8_t list_len = exts[off];
          if(list_len >= 2 && 1 + list_len <= ext_len) {
            *out_version = be16(exts + off + 1);
          }
        }
      }
    }

    off += ext_len;
  }

  return found_any;
}

/* Parse ClientHello or ServerHello body */
static int parse_hello(const uint8_t *body, size_t len, int is_server_hello,
                      uint16_t *out_group, char *out_name, size_t out_cap,
                      char *out_sni, size_t sni_cap,
                      uint16_t *out_cipher, char *out_cipher_name, size_t cipher_cap,
                      uint16_t *out_version) {
  if(len < 34) return 0;

  /* Extract TLS version from first 2 bytes */
  uint16_t version = be16(body);
  if(out_version) *out_version = version;

  size_t off = 2 + 32; /* Skip version + random */

  if(!is_server_hello) {
    /* ClientHello: [session_id_len:1][session_id][...] */
    if(off + 1 > len) return 0;
    uint8_t sid_len = body[off++];
    if(off + sid_len > len) return 0;
    off += sid_len;

    /* [cipher_suites_len:2][cipher_suites] */
    if(off + 2 > len) return 0;
    uint16_t cs_len = be16(body + off);
    off += 2;
    if(off + cs_len > len) return 0;
    off += cs_len;

    /* [compression_methods_len:1][compression_methods] */
    if(off + 1 > len) return 0;
    uint8_t cm_len = body[off++];
    if(off + cm_len > len) return 0;
    off += cm_len;
  } else {
    /* ServerHello: [version:2][random:32][session_id_len:1][session_id][cipher:2][compression:1][exts] */
    if(off + 1 > len) return 0;
    uint8_t sid_len = body[off++];
    if(off + sid_len + 3 > len) return 0; /* sid + cipher(2) + compression(1) */
    off += sid_len;

    /* Extract cipher suite (2 bytes) */
    uint16_t cipher_id = be16(body + off);
    if(out_cipher) *out_cipher = cipher_id;
    if(out_cipher_name) {
      const char *name = cipher_id_to_name(cipher_id);
      if(name) {
        strncpy(out_cipher_name, name, cipher_cap - 1);
        out_cipher_name[cipher_cap - 1] = '\0';
      } else {
        snprintf(out_cipher_name, cipher_cap, "0x%04X", cipher_id);
      }
    }
    off += 3; /* cipher(2) + compression(1) */
  }

  /* Extensions: [extensions_len:2][extension_list] */
  if(off + 2 > len) return 0;
  uint16_t exts_len = be16(body + off);
  off += 2;
  if(off + exts_len > len) return 0;

  return parse_extensions(body + off, exts_len, out_group, out_name, out_cap,
                         out_sni, sni_cap, is_server_hello, out_version);
}

/* Parse Certificate message and extract leaf cert fingerprint
 * Certificate message format (TLS 1.2):
 *   [certificates_length:3][cert_data:3+len][cert_data:3+len]...
 * Each cert_data:
 *   [cert_length:3][DER-encoded X.509 certificate]
 */
static int parse_certificate(const uint8_t *body, size_t len,
                             char *out_fingerprint, size_t fp_cap,
                             char *out_subject, size_t subj_cap,
                             char *out_issuer, size_t issuer_cap) {
  if(len < 3) return 0;

  /* Total length of certificate chain */
  uint32_t certs_len = be24(body);
  if(3 + certs_len > len) return 0;

  size_t off = 3;

  /* Parse first (leaf) certificate only */
  if(off + 3 > len) return 0;
  uint32_t cert_len = be24(body + off);
  off += 3;

  if(off + cert_len > len || cert_len == 0) return 0;

  const uint8_t *cert_der = body + off;

  /* Compute SHA256 fingerprint of DER-encoded certificate */
  if(out_fingerprint && fp_cap >= 65) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(cert_der, cert_len, hash);

    /* Convert to hex string */
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
      snprintf(out_fingerprint + (i * 2), 3, "%02x", hash[i]);
    }
    out_fingerprint[64] = '\0';
  }

  /* Parse X.509 certificate for subject/issuer */
  if(out_subject || out_issuer) {
    const unsigned char *p = cert_der;
    X509 *x509 = d2i_X509(NULL, &p, cert_len);
    if(x509) {
      if(out_subject && subj_cap > 0) {
        X509_NAME *subj = X509_get_subject_name(x509);
        if(subj) {
          X509_NAME_oneline(subj, out_subject, subj_cap);
        }
      }
      if(out_issuer && issuer_cap > 0) {
        X509_NAME *iss = X509_get_issuer_name(x509);
        if(iss) {
          X509_NAME_oneline(iss, out_issuer, issuer_cap);
        }
      }
      X509_free(x509);
    }
  }

  return 1;
}

/* Public FSM */
tlspqc_rc tls_pqc_feed(tls_pqc_fsm *f,
                       const uint8_t *payload, size_t plen,
                       char *out_group, size_t out_cap)
{
  if(!payload || plen == 0) return TLSPQC_IN_PROGRESS;
  if(f->st == TLS_S_DONE) {
    if(out_group && f->negotiated_group[0]) {
      strncpy(out_group, f->negotiated_group, out_cap - 1);
      out_group[out_cap - 1] = '\0';
    }
    return f->negotiated_group[0] ? TLSPQC_FOUND_PQC : TLSPQC_FOUND_CLASSIC;
  }
  if(f->st == TLS_S_FAIL) return TLSPQC_FAIL;

  size_t off = 0;

  /* State machine */
  while(off < plen) {
    if(f->st == TLS_S_START) f->st = TLS_S_REC_HDR;

    /* Read TLS record header: [type:1][version:2][length:2] */
    if(f->st == TLS_S_REC_HDR) {
      while(f->rec_hdr_have < 5 && off < plen) {
        f->rec_hdr[f->rec_hdr_have++] = payload[off++];
      }
      if(f->rec_hdr_have < 5) return TLSPQC_IN_PROGRESS;

      f->rec_type = f->rec_hdr[0];
      f->rec_len = be16(f->rec_hdr + 3);

      /* Only process Handshake records */
      if(f->rec_type != TLS_RECORD_HANDSHAKE) {
        /* Skip non-handshake record */
        f->rec_hdr_have = 0;
        if(f->rec_len > 0 && off + f->rec_len <= plen) {
          off += f->rec_len;
        } else {
          /* Record spans multiple TCP segments - give up */
          f->st = TLS_S_FAIL;
          return TLSPQC_FAIL;
        }
        continue;
      }

      /* Sanity check */
      if(f->rec_len > sizeof(f->body) || f->rec_len < 4) {
        f->rec_hdr_have = 0;
        continue; /* Skip oversized or tiny records */
      }

      f->st = TLS_S_HS_HDR;
      f->hs_hdr_have = 0;
    }

    /* Read handshake header: [msg_type:1][length:3] */
    if(f->st == TLS_S_HS_HDR) {
      while(f->hs_hdr_have < 4 && off < plen) {
        f->hs_hdr[f->hs_hdr_have++] = payload[off++];
      }
      if(f->hs_hdr_have < 4) return TLSPQC_IN_PROGRESS;

      f->hs_type = f->hs_hdr[0];
      f->hs_len = be24(f->hs_hdr + 1);

      /* Only parse ClientHello, ServerHello, or Certificate */
      if(f->hs_type != TLS_HS_CLIENT_HELLO &&
         f->hs_type != TLS_HS_SERVER_HELLO &&
         f->hs_type != TLS_HS_CERTIFICATE) {
        /* Reset to try next record */
        f->rec_hdr_have = 0;
        f->hs_hdr_have = 0;
        f->st = TLS_S_REC_HDR;
        continue;
      }

      /* Sanity */
      if(f->hs_len > sizeof(f->body) || f->hs_len == 0) {
        f->rec_hdr_have = 0;
        f->hs_hdr_have = 0;
        f->st = TLS_S_REC_HDR;
        continue;
      }

      f->body_need = f->hs_len;
      f->body_have = 0;
      f->st = TLS_S_HS_BODY;
    }

    /* Accumulate handshake body */
    if(f->st == TLS_S_HS_BODY) {
      while(f->body_have < f->body_need && off < plen) {
        f->body[f->body_have++] = payload[off++];
      }
      if(f->body_have < f->body_need) return TLSPQC_IN_PROGRESS;

      /* Handle Certificate message separately */
      if(f->hs_type == TLS_HS_CERTIFICATE) {
        if(parse_certificate(f->body, f->body_have,
                             f->cert_fingerprint, sizeof(f->cert_fingerprint),
                             f->cert_subject, sizeof(f->cert_subject),
                             f->cert_issuer, sizeof(f->cert_issuer))) {
          f->seen_certificate = 1;
        }
        /* After Certificate, we have what we need - mark as done */
        f->st = TLS_S_DONE;
        return f->negotiated_group[0] ? TLSPQC_FOUND_PQC : TLSPQC_FOUND_CLASSIC;
      }

      /* Parse the hello message */
      uint16_t gid = 0;
      char gname[64] = {0};
      char sni[256] = {0};
      uint16_t cipher_id = 0;
      char cipher_name[64] = {0};
      uint16_t hello_version = 0;
      int is_sh = (f->hs_type == TLS_HS_SERVER_HELLO);

      int parsed = parse_hello(f->body, f->body_have, is_sh, &gid, gname, sizeof(gname),
                     sni, sizeof(sni), &cipher_id, cipher_name, sizeof(cipher_name),
                     &hello_version);

      /* Always store TLS version in FSM (even if no PQC groups found) */
      if(hello_version) {
        if(is_sh) {
          f->negotiated_version = hello_version;
        } else {
          f->offered_version = hello_version;
        }
      }

      if(parsed) {
        if(is_pqc_group(gid)) {
          strncpy(f->negotiated_group, gname, sizeof(f->negotiated_group) - 1);
          f->negotiated_group[sizeof(f->negotiated_group) - 1] = '\0';
          if(out_group) {
            strncpy(out_group, gname, out_cap - 1);
            out_group[out_cap - 1] = '\0';
          }
          f->st = TLS_S_DONE;
          return TLSPQC_FOUND_PQC;
        } else if(gname[0]) {
          /* Found classical group */
          strncpy(f->negotiated_group, gname, sizeof(f->negotiated_group) - 1);
          if(out_group) {
            strncpy(out_group, gname, out_cap - 1);
            out_group[out_cap - 1] = '\0';
          }
        }
      }

      /* Store extracted metadata in FSM */
      if(sni[0] && !f->server_name[0]) {
        strncpy(f->server_name, sni, sizeof(f->server_name) - 1);
      }
      if(cipher_name[0]) {
        strncpy(f->cipher_suite, cipher_name, sizeof(f->cipher_suite) - 1);
        f->cipher_id = cipher_id;
      }

      /* Mark which hello we've seen */
      if(is_sh) {
        f->seen_server_hello = 1;
        /* Continue parsing to capture Certificate (comes after ServerHello in TLS 1.2) */
        f->rec_hdr_have = 0;
        f->hs_hdr_have = 0;
        f->st = TLS_S_REC_HDR;
      } else {
        f->seen_client_hello = 1;
        /* Continue to look for ServerHello */
        f->rec_hdr_have = 0;
        f->hs_hdr_have = 0;
        f->st = TLS_S_REC_HDR;
      }
    }
  }

  return TLSPQC_IN_PROGRESS;
}
