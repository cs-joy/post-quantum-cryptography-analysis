#ifndef TINY_HASH_H
#define TINY_HASH_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct th_node {
  void *key;
  size_t keylen;
  void *val;
  struct th_node *next;
} th_node;

typedef struct {
  th_node **buckets;
  size_t nbuckets;
} th_table;

static inline uint32_t th_hash(const void *key, size_t len) {
  // simple djb2
  const unsigned char *p = (const unsigned char*)key;
  uint32_t h = 5381;
  for(size_t i=0;i<len;i++) h = ((h<<5)+h) + p[i];
  return h;
}

static inline th_table *th_create(size_t nbuckets) {
  th_table *t = (th_table*)calloc(1,sizeof(th_table));
  t->nbuckets = nbuckets ? nbuckets : 256;
  t->buckets = (th_node**)calloc(t->nbuckets, sizeof(th_node*));
  return t;
}

static inline void th_free(th_table *t, void (*free_val)(void*)) {
  if(!t) return;
  for(size_t i=0;i<t->nbuckets;i++) {
    th_node *n=t->buckets[i];
    while(n){ th_node *nx=n->next; free(n->key); if(free_val) free_val(n->val); free(n); n=nx; }
  }
  free(t->buckets); free(t);
}

static inline void *th_get(th_table *t, const void *key, size_t keylen) {
  if(!t) return NULL;
  uint32_t h = th_hash(key, keylen);
  th_node *n = t->buckets[h % t->nbuckets];
  while(n){
    if(n->keylen==keylen && memcmp(n->key,key,keylen)==0) return n->val;
    n=n->next;
  }
  return NULL;
}

static inline void th_put(th_table *t, const void *key, size_t keylen, void *val) {
  if(!t) return;
  uint32_t h = th_hash(key, keylen);
  size_t idx = h % t->nbuckets;
  th_node *n = (th_node*)calloc(1,sizeof(th_node));
  n->key = malloc(keylen);
  memcpy(n->key, key, keylen);
  n->keylen = keylen;
  n->val = val;
  n->next = t->buckets[idx];
  t->buckets[idx] = n;
}

#endif