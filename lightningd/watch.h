#ifndef LIGHTNING_LIGHTNINGD_WATCH_H
#define LIGHTNING_LIGHTNINGD_WATCH_H
#include "config.h"
#include <zcore/tx.h>
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/htable/htable_type.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/typesafe_cb/typesafe_cb.h>

struct zcore_tx;
struct block;
struct channel;
struct chain_topology;
struct lightningd;
struct txowatch;
struct txwatch;

enum watch_result {
	DELETE_WATCH = -1,
	KEEP_WATCHING = -2
};

struct txwatch_output {
	struct zcore_txid txid;
	unsigned int index;
};

const struct txwatch_output *txowatch_keyof(const struct txowatch *w);
size_t txo_hash(const struct txwatch_output *out);
bool txowatch_eq(const struct txowatch *w, const struct txwatch_output *out);

HTABLE_DEFINE_TYPE(struct txowatch, txowatch_keyof, txo_hash, txowatch_eq,
		   txowatch_hash);

const struct zcore_txid *txwatch_keyof(const struct txwatch *w);
size_t txid_hash(const struct zcore_txid *txid);
bool txwatch_eq(const struct txwatch *w, const struct zcore_txid *txid);
HTABLE_DEFINE_TYPE(struct txwatch, txwatch_keyof, txid_hash, txwatch_eq,
		   txwatch_hash);


struct txwatch *watch_txid(const tal_t *ctx,
			   struct chain_topology *topo,
			   struct channel *channel,
			   const struct zcore_txid *txid,
			   enum watch_result (*cb)(struct lightningd *ld,
						   struct channel *channel,
						   const struct zcore_txid *,
						   const struct zcore_tx *,
						   unsigned int depth));

struct txwatch *watch_tx(const tal_t *ctx,
			 struct chain_topology *topo,
			 struct channel *channel,
			 const struct zcore_tx *tx,
			 enum watch_result (*cb)(struct lightningd *ld,
						 struct channel *channel,
						 const struct zcore_txid *,
						 const struct zcore_tx *,
						 unsigned int depth));

struct txowatch *watch_txo(const tal_t *ctx,
			   struct chain_topology *topo,
			   struct channel *channel,
			   const struct zcore_txid *txid,
			   unsigned int output,
			   enum watch_result (*cb)(struct channel *channel,
						   const struct zcore_tx *tx,
						   size_t input_num,
						   const struct block *block));

struct txwatch *find_txwatch(struct chain_topology *topo,
			     const struct zcore_txid *txid,
			     const struct channel *channel);

void txwatch_fire(struct chain_topology *topo,
		  const struct zcore_txid *txid,
		  unsigned int depth);

void txowatch_fire(const struct txowatch *txow,
		   const struct zcore_tx *tx, size_t input_num,
		   const struct block *block);

bool watching_txid(const struct chain_topology *topo,
		   const struct zcore_txid *txid);

/* FIXME: Implement zcore_tx_dup() so we tx arg can be TAKEN */
void txwatch_inform(const struct chain_topology *topo,
		    const struct zcore_txid *txid,
		    const struct zcore_tx *tx_may_steal);

void watch_topology_changed(struct chain_topology *topo);
#endif /* LIGHTNING_LIGHTNINGD_WATCH_H */
