/* uthash.h: https://troydhanson.github.io/uthash/  (public domain) */
#ifndef UTHASH_H
#define UTHASH_H
#define uthash_fatal(msg) exit(-1)
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
typedef struct UT_hash_bucket {
   struct UT_hash_handle *hh_head;
   unsigned count;
   unsigned expand_mult;
} UT_hash_bucket;
typedef struct UT_hash_table {
   UT_hash_bucket *buckets;
   unsigned num_buckets, log2_num_buckets;
   unsigned num_items;
   unsigned ideal_chain_maxlen, nonideal_items, ineff_expands, noexpand;
   uint32_t signature;
   void *tail;
   ptrdiff_t hho;
   size_t keylen;
} UT_hash_table;
typedef struct UT_hash_handle {
   struct UT_hash_table *tbl;
   void *prev;
   void *next;
   struct UT_hash_handle *hh_prev;
   struct UT_hash_handle *hh_next;
   void *key;
   unsigned keylen;
   unsigned hashv;
} UT_hash_handle;
#define HASH_FIND(hh,head,keyptr,keylen,out)                                          \
do { out=NULL;                                                                        \
     if (head) {                                                                      \
       UT_hash_handle *_hf_hash_handle = (head)->hh.tbl ? (head)->hh.tbl->tail : NULL;\
       UT_hash_table *_hf_tbl = (head)->hh.tbl;                                       \
       if (_hf_tbl) {                                                                 \
         unsigned _hf_hashv = 0;                                                      \
         for (unsigned _i=0; _i<(keylen); ++_i) _hf_hashv = _hf_hashv*33 + ((unsigned char*)keyptr)[_i];\
         unsigned _hf_bucket = _hf_hashv & (_hf_tbl->num_buckets-1);                  \
         UT_hash_handle *_hf_hh = _hf_tbl->buckets[_hf_bucket].hh_head;               \
         while (_hf_hh) {                                                             \
           if ((_hf_hh->keylen == (keylen)) && (memcmp(_hf_hh->key, keyptr, keylen)==0)) { out = (void*)(((char*)_hf_hh) - _hf_tbl->hho); break; }\
           _hf_hh = _hf_hh->hh_next;                                                  \
         }                                                                            \
       }                                                                              \
     }                                                                                \
} while (0)
#define HASH_ADD(hh,head,fieldname,keylen_in,add)                                     \
do {                                                                                  \
  if (!(head)) {                                                                      \
    (head) = (add);                                                                   \
    (head)->hh.tbl = (UT_hash_table*)calloc(1, sizeof(UT_hash_table));                \
    (head)->hh.tbl->num_buckets = 32;                                                 \
    (head)->hh.tbl->log2_num_buckets = 5;                                            \
    (head)->hh.tbl->buckets = (UT_hash_bucket*)calloc((head)->hh.tbl->num_buckets,sizeof(UT_hash_bucket));\
    (head)->hh.tbl->hho = (char*)&((typeof(head))0)->hh - (char*)0 + offsetof(typeof(*(head)), hh) - offsetof(typeof(*(head)), hh);\
  }                                                                                   \
  (add)->hh.key = (void*)&((add)->fieldname);                                         \
  (add)->hh.keylen = (keylen_in);                                                     \
  unsigned _hf_hashv = 0;                                                             \
  for (unsigned _i=0; _i<(keylen_in); ++_i) _hf_hashv = _hf_hashv*33 + ((unsigned char*)((add)->hh.key))[_i];\
  (add)->hh.hashv = _hf_hashv;                                                        \
  (add)->hh.tbl = (head)->hh.tbl;                                                     \
  unsigned _hf_bucket = _hf_hashv & ((head)->hh.tbl->num_buckets-1);                  \
  (add)->hh.hh_next = (head)->hh.tbl->buckets[_hf_bucket].hh_head;                    \
  (head)->hh.tbl->buckets[_hf_bucket].hh_head = &((add)->hh);                         \
  (head)->hh.tbl->num_items++;                                                        \
} while (0)
#define HASH_DEL(head,delptr)                                                         \
do {                                                                                  \
  if ((head) && (delptr)) {                                                           \
    UT_hash_table *_tbl = (head)->hh.tbl;                                             \
    unsigned _hf_bucket = (delptr)->hh.hashv & (_tbl->num_buckets-1);                 \
    UT_hash_handle **pprev = &_tbl->buckets[_hf_bucket].hh_head;                      \
    UT_hash_handle *cur = _tbl->buckets[_hf_bucket].hh_head;                          \
    while (cur) {                                                                     \
      if (cur == &((delptr)->hh)) { *pprev = cur->hh_next; break; }                   \
      pprev = &cur->hh_next; cur = cur->hh_next;                                      \
    }                                                                                 \
    _tbl->num_items--;                                                                \
  }                                                                                   \
} while (0)
#endif