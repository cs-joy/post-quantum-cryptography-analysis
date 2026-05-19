// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Copyright (c) 2025 Graziano Labs Corp.
 */

#ifndef FLOW_H
#define FLOW_H

#include <stdint.h>
#include <time.h>
#include "pqc_detect.h"

typedef struct {
  uint32_t src_ip, dst_ip;
  uint16_t src_port, dst_port;
  uint8_t  l4_proto; // 6=TCP,17=UDP
  uint64_t first_seen_ts, last_seen_ts;

  FlowMeta meta;
} FlowRecord;

#endif