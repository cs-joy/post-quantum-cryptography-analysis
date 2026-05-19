// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Copyright (c) 2025 Graziano Labs Corp.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#include "flow.h"
#include "ndpi_glue.h"
#include "afpacket_capture.h"

static void usage(const char *prog){
  fprintf(stderr,
    "Usage:\n"
    "  %s --mock\n"
    "  %s <file.pcap>\n"
    "  %s --live <iface> [--fanout N] [--snaplen BYTES]\n\n"
    "Examples:\n"
    "  %s --mock\n"
    "  %s pqc-sample.pcap\n"
    "  %s --live eth0 --fanout 123 --snaplen 4096\n",
    prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv) {
  static struct option longopts[] = {
    {"mock",    no_argument,       0,  1},
    {"live",    required_argument, 0,  2},
    {"fanout",  required_argument, 0,  3},
    {"snaplen", required_argument, 0,  4},
    {"help",    no_argument,       0, 'h'},
    {0,0,0,0}
  };

  int opt, idx=0;
  int do_mock=0;
  const char *pcap_path=NULL;
  const char *iface=NULL;
  int fanout_id=0;
  int snaplen=0;

  while((opt = getopt_long(argc, argv, "h", longopts, &idx)) != -1){
    switch(opt){
      case 1: do_mock=1; break;
      case 2: iface = optarg; break;
      case 3: fanout_id = atoi(optarg); break;
      case 4: snaplen = atoi(optarg); break;
      case 'h': usage(argv[0]); return 0;
      default: usage(argv[0]); return 1;
    }
  }
  if(optind < argc) pcap_path = argv[optind];

  if(do_mock){
    FlowRecord fr = {0};
    strcpy(fr.meta.tls_supported_groups, "x25519, ml-kem-768");
    strcpy(fr.meta.tls_negotiated_group, "X25519+ML-KEM-768");
    strcpy(fr.meta.ssh_kex_negotiated, "sntrup761x25519-sha512@openssh.com");
    pqc_from_strings(&fr.meta, "tls",
      fr.meta.tls_supported_groups, fr.meta.tls_negotiated_group,
      fr.meta.tls_sig_algs, fr.meta.tls_server_sigalg);
    pqc_from_strings(&fr.meta, "ssh",
      fr.meta.ssh_kex_offered, fr.meta.ssh_kex_negotiated,
      fr.meta.ssh_hostkey_offered, fr.meta.ssh_sig_alg);
    printf("{\"pqc_flags\":%u,\"pqc_reason\":\"%s\",\"tls_negotiated_group\":\"%s\",\"ssh_kex_negotiated\":\"%s\"}\n",
           fr.meta.pqc_flags, fr.meta.pqc_reason,
           fr.meta.tls_negotiated_group, fr.meta.ssh_kex_negotiated);
    return 0;
  }

  if(iface){
    NdpiCtx ctx;
    if(ndpi_glue_init(&ctx) != 0) { fprintf(stderr,"nDPI init failed\n"); return 2; }
    int rc = run_afpacket(iface, &ctx, fanout_id, snaplen);
    ndpi_glue_finish(&ctx);
    return (rc==0)?0:2;
  }

  if(pcap_path){
    extern void process_pcap(const char *pcap_file); // already implemented
    process_pcap(pcap_path);
    return 0;
  }

  usage(argv[0]);
  return 1;
}