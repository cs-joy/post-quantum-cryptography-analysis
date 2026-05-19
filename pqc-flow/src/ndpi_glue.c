// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Copyright (c) 2025 Graziano Labs Corp.
 */

#include "ndpi_glue.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#if __has_include(<ndpi/ndpi_api.h>)
  #include <ndpi/ndpi_api.h>
#elif __has_include(<ndpi_api.h>)
  #include <ndpi_api.h>
#else
  #error "Cannot find nDPI headers (ndpi_api.h)"
#endif

/* ---------------- helpers ---------------- */

static inline void copy_str(char *dst, const char *src, size_t cap) {
  if(!dst || cap==0) return;
  if(!src) { dst[0]='\0'; return; }
  strncpy(dst, src, cap-1); dst[cap-1]='\0';
}

/* tiny key:"value" extractor (sufficient for ndpi JSON) */
static int json_get_string(const char *json, const char *key, char *out, size_t outcap) {
  if(!json || !key || !out || outcap==0) return 0;
  out[0]='\0';
  char pat[128];
  snprintf(pat,sizeof(pat),"\"%s\"",key);
  const char *k = strstr(json, pat);
  if(!k) return 0;
  const char *colon = strchr(k+strlen(pat), ':'); if(!colon) return 0;
  const char *v = colon+1; while(*v==' '||*v=='\t') v++;
  if(*v=='\"') {
    v++;
    const char *e = strchr(v,'\"'); if(!e) return 0;
    size_t n = (size_t)(e-v); if(n>=outcap) n=outcap-1;
    memcpy(out,v,n); out[n]='\0'; return 1;
  } else {
    const char *e=v; while(*e && *e!=',' && *e!='}' && *e!='\n') e++;
    size_t n = (size_t)(e-v); if(n>=outcap) n=outcap-1;
    memcpy(out,v,n); out[n]='\0'; return 1;
  }
}

/* ---------------- init/finish ---------------- */

static struct ndpi_global_context *gctx = NULL;

int ndpi_glue_init(NdpiCtx *ctx) {
  memset(ctx,0,sizeof(*ctx));
  #ifdef ndpi_global_init
    if(!gctx) gctx = ndpi_global_init();
  #endif
  ctx->dm = ndpi_init_detection_module(gctx);
  if(!ctx->dm) return -1;

  /* Enable all protocols - create bitmask with all set */
  NDPI_PROTOCOL_BITMASK all;
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ctx->dm, &all);

  ndpi_finalize_initialization(ctx->dm);
  return 0;
}

void ndpi_glue_finish(NdpiCtx *ctx) {
  if(ctx && ctx->dm) {
    ndpi_exit_detection_module(ctx->dm);
    ctx->dm = NULL;
  }
  /* Note: ndpi_global_cleanup(gctx) optional for process shutdown */
}

/* ---------------- flow alloc ---------------- */

static inline size_t guess_flow_size(void) {
#ifdef NDPI_FLOW_STRUCT_SIZE
  return NDPI_FLOW_STRUCT_SIZE;
#else
  return 16384; /* Safe default for nDPI 4.x if macro not defined */
#endif
}

static inline void ensure_flow(NdpiFlowWrap *fw) {
  if(!fw->ndpi_flow) {
    size_t sz = guess_flow_size();
    fw->ndpi_flow = (struct ndpi_flow_struct*) ndpi_flow_malloc(sz);
    if(fw->ndpi_flow) memset(fw->ndpi_flow, 0, sz);
  }
}

/* ---------------- packet processing ---------------- */

int ndpi_glue_process_packet(NdpiCtx *ctx, NdpiFlowWrap *fw,
                             const uint8_t *pkt, uint16_t len,
                             uint64_t ts_usec, int direction)
{
  if(!ctx || !ctx->dm || !fw || !pkt || !len) return -1;
  ensure_flow(fw);

  const uint64_t tick = ts_usec;

  /* Fill ndpi_flow_input_info for proper L7 dissection */
  struct ndpi_flow_input_info input_info;
  memset(&input_info, 0, sizeof(input_info));
  input_info.in_pkt_dir = (unsigned char)(direction & 1);
  input_info.seen_flow_beginning = 1; /* We track from flow start */

  ndpi_protocol pr = ndpi_detection_process_packet(ctx->dm, fw->ndpi_flow,
                                                 pkt, len, tick,
                                                 &input_info);

  /* Serialize flow to JSON for metadata extraction */
  ndpi_serializer s;
  ndpi_init_serializer(&s, ndpi_serialization_format_json);

  /* nDPI 4.11 signature: (module, serializer, risk, confidence, protocol) */
  ndpi_serialize_proto(ctx->dm, &s,
                      0, /* risk */
  #ifdef NDPI_CONFIDENCE_UNKNOWN
                      NDPI_CONFIDENCE_UNKNOWN,
  #else
                      0, /* confidence */
  #endif
                      pr /* detected protocol */);


  /* Extract metadata from nDPI JSON serialization */
  u_int32_t js_len = 0;
  const char *js = ndpi_serializer_get_buffer(&s, &js_len);

  if(js && js_len) {
    /* TLS/DTLS fields */
    json_get_string(js, "client_supported_groups", fw->meta.tls_supported_groups, sizeof(fw->meta.tls_supported_groups));
    json_get_string(js, "server_selected_group",   fw->meta.tls_negotiated_group, sizeof(fw->meta.tls_negotiated_group));
    json_get_string(js, "client_sig_algs",         fw->meta.tls_sig_algs,         sizeof(fw->meta.tls_sig_algs));
    json_get_string(js, "server_sig_alg",          fw->meta.tls_server_sigalg,    sizeof(fw->meta.tls_server_sigalg));

    /* QUIC uses TLS fields (TLS-in-QUIC) */
    if(fw->meta.tls_supported_groups[0] || fw->meta.tls_negotiated_group[0]) {
      copy_str(fw->meta.quic_tls_supported_groups, fw->meta.tls_supported_groups, sizeof(fw->meta.quic_tls_supported_groups));
      copy_str(fw->meta.quic_tls_negotiated_group, fw->meta.tls_negotiated_group, sizeof(fw->meta.quic_tls_negotiated_group));
      copy_str(fw->meta.quic_tls_sig_algs,         fw->meta.tls_sig_algs,         sizeof(fw->meta.quic_tls_sig_algs));
    }

    /* SSH fields */
    json_get_string(js, "ssh.kex",            fw->meta.ssh_kex_negotiated, sizeof(fw->meta.ssh_kex_negotiated));
    json_get_string(js, "ssh.kex_algorithms", fw->meta.ssh_kex_offered,    sizeof(fw->meta.ssh_kex_offered));
    json_get_string(js, "ssh.sig_alg",        fw->meta.ssh_sig_alg,        sizeof(fw->meta.ssh_sig_alg));

    /* IKE fields */
    json_get_string(js, "ike.ke_chosen",  fw->meta.ike_ke_chosen,  sizeof(fw->meta.ike_ke_chosen));
    json_get_string(js, "ike.ke_offered", fw->meta.ike_ke_offered, sizeof(fw->meta.ike_ke_offered));
  }

  ndpi_term_serializer(&s);
  return 0;
}

int ndpi_glue_handshake_done(NdpiFlowWrap *fw) {
  if(!fw) return 0;
  if(fw->meta.tls_negotiated_group[0]) return 1;
  if(fw->meta.quic_tls_negotiated_group[0]) return 1;
  if(fw->meta.ssh_kex_negotiated[0]) return 1;
  if(fw->meta.ike_ke_chosen[0]) return 1;
  return 0;
}
