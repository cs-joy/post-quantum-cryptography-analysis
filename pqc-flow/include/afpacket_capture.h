// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Copyright (c) 2025 Graziano Labs Corp.
 */

#ifndef AFPACKET_CAPTURE_H
#define AFPACKET_CAPTURE_H

#include <stdint.h>
#include "ndpi_glue.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Run a live AF_PACKET (TPACKET_V3) capture on `iface`.
 * fanout_id: 0 to disable fanout; otherwise a group id shared by workers.
 * snaplen: bytes to capture from L2 onward per frame (suggest 2048..4096).
 * Returns 0 on clean stop, <0 on error.
 */
int run_afpacket(const char *iface, NdpiCtx *ctx, int fanout_id, int snaplen);

#ifdef __cplusplus
}
#endif

#endif /* AFPACKET_CAPTURE_H */