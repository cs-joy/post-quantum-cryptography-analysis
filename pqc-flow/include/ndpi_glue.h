// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Copyright (c) 2025 Graziano Labs Corp.
 */

#ifndef NDPI_GLUE_H
#define NDPI_GLUE_H

#include "flow.h"  // for FlowMeta

/* Forward decls only; avoid pulling ndpi_api.h in this header */
struct ndpi_detection_module_struct;
struct ndpi_flow_struct;

typedef struct {
  struct ndpi_flow_struct *ndpi_flow; /* allocated in ndpi_glue.c */
  FlowMeta meta;
} NdpiFlowWrap;

typedef struct {
  struct ndpi_detection_module_struct *dm; /* set in ndpi_glue.c */
} NdpiCtx;

/* Glue API */
int  ndpi_glue_init(NdpiCtx *ctx);
void ndpi_glue_finish(NdpiCtx *ctx);

int  ndpi_glue_process_packet(NdpiCtx *ctx, NdpiFlowWrap *fw,
                              const uint8_t *pkt, uint16_t len,
                              uint64_t ts_usec, int direction);

int  ndpi_glue_handshake_done(NdpiFlowWrap *fw);

#endif /* NDPI_GLUE_H */
