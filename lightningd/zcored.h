#ifndef LIGHTNING_LIGHTNINGD_ZCORED_H
#define LIGHTNING_LIGHTNINGD_ZCORED_H
#include "config.h"
#include <zcore/chainparams.h>
#include <zcore/tx.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <stdbool.h>

struct zcore_blkid;
struct zcore_tx_output;
struct block;
struct lightningd;
struct ripemd160;
struct zcore_tx;
struct zcore_block;

enum zcored_prio {
	ZCORED_LOW_PRIO,
	ZCORED_HIGH_PRIO
};
#define ZCORED_NUM_PRIO (ZCORED_HIGH_PRIO+1)

struct zcored {
	/* eg. "zcore-cli" */
	char *cli;

	/* -datadir arg for zcore-cli. */
	char *datadir;

	/* Where to do logging. */
	struct log *log;

	/* Main lightningd structure */
	struct lightningd *ld;

	/* Is zcored synced?  If not, we retry. */
	bool synced;

	/* How many high/low prio requests are we running (it's ratelimited) */
	size_t num_requests[ZCORED_NUM_PRIO];

	/* Pending requests (high and low prio). */
	struct list_head pending[ZCORED_NUM_PRIO];

	/* What network are we on? */
	const struct chainparams *chainparams;

	/* If non-zero, time we first hit a zcored error. */
	unsigned int error_count;
	struct timemono first_error_time;

	/* Ignore results, we're shutting down. */
	bool shutdown;

	/* How long to keep trying to contact zcored
	 * before fatally exiting. */
	u64 retry_timeout;

	/* Passthrough parameters for zcore-cli */
	char *rpcuser, *rpcpass, *rpcconnect, *rpcport;

	struct list_head pending_getfilteredblock;
};

/* A single outpoint in a filtered block */
struct filteredblock_outpoint {
	struct zcore_txid txid;
	u32 outnum;
	u32 txindex;
	const u8 *scriptPubKey;
	struct amount_sat amount;
};

/* A struct representing a block with most of the parts filtered out. */
struct filteredblock {
	struct zcore_blkid id;
	u32 height;
	struct zcore_blkid prev_hash;
	struct filteredblock_outpoint **outpoints;
};

struct zcored *new_zcored(const tal_t *ctx,
			      struct lightningd *ld,
			      struct log *log);

void wait_for_zcored(struct zcored *zcored);

void zcored_estimate_fees_(struct zcored *zcored,
			     const u32 blocks[], const char *estmode[],
			     size_t num_estimates,
			     void (*cb)(struct zcored *zcored,
					const u32 satoshi_per_kw[], void *),
			     void *arg);

#define zcored_estimate_fees(zcored_, blocks, estmode, num, cb, arg) \
	zcored_estimate_fees_((zcored_), (blocks), (estmode), (num), \
				typesafe_cb_preargs(void, void *,	\
						    (cb), (arg),	\
						    struct zcored *,	\
						    const u32 *),	\
				(arg))

void zcored_sendrawtx_(struct zcored *zcored,
			 const char *hextx,
			 void (*cb)(struct zcored *zcored,
				    int exitstatus, const char *msg, void *),
			 void *arg);

#define zcored_sendrawtx(zcored_, hextx, cb, arg)			\
	zcored_sendrawtx_((zcored_), (hextx),			\
			    typesafe_cb_preargs(void, void *,		\
						(cb), (arg),		\
						struct zcored *,	\
						int, const char *),	\
			    (arg))

void zcored_getblockcount_(struct zcored *zcored,
			     void (*cb)(struct zcored *zcored,
					u32 blockcount,
					void *arg),
			     void *arg);

#define zcored_getblockcount(zcored_, cb, arg)			\
	zcored_getblockcount_((zcored_),				\
				typesafe_cb_preargs(void, void *,	\
						    (cb), (arg),	\
						    struct zcored *,	\
						    u32 blockcount),	\
				(arg))

/* blkid is NULL if call fails. */
void zcored_getblockhash_(struct zcored *zcored,
			    u32 height,
			    void (*cb)(struct zcored *zcored,
				       const struct zcore_blkid *blkid,
				       void *arg),
			    void *arg);
#define zcored_getblockhash(zcored_, height, cb, arg)		\
	zcored_getblockhash_((zcored_),				\
			       (height),				\
			       typesafe_cb_preargs(void, void *,	\
						   (cb), (arg),		\
						   struct zcored *,	\
						   const struct zcore_blkid *), \
			       (arg))

void zcored_getfilteredblock_(struct zcored *zcored, u32 height,
				void (*cb)(struct zcored *zcored,
					   const struct filteredblock *fb,
					   void *arg),
				void *arg);
#define zcored_getfilteredblock(zcored_, height, cb, arg)		\
	zcored_getfilteredblock_((zcored_),				\
				   (height),				\
				   typesafe_cb_preargs(void, void *,	\
						       (cb), (arg),	\
						       struct zcored *, \
						       const struct filteredblock *), \
				   (arg))

void zcored_getrawblock_(struct zcored *zcored,
			   const struct zcore_blkid *blockid,
			   void (*cb)(struct zcored *zcored,
				      struct zcore_block *blk,
				      void *arg),
			   void *arg);
#define zcored_getrawblock(zcored_, blkid, cb, arg)			\
	zcored_getrawblock_((zcored_), (blkid),			\
			      typesafe_cb_preargs(void, void *,		\
						  (cb), (arg),		\
						  struct zcored *,	\
						  struct zcore_block *), \
			      (arg))

void zcored_getoutput_(struct zcored *zcored,
			 unsigned int blocknum, unsigned int txnum,
			 unsigned int outnum,
			 void (*cb)(struct zcored *zcored,
				    const struct zcore_tx_output *output,
				    void *arg),
			 void *arg);
#define zcored_getoutput(zcored_, blocknum, txnum, outnum, cb, arg)	\
	zcored_getoutput_((zcored_), (blocknum), (txnum), (outnum),	\
			    typesafe_cb_preargs(void, void *,		\
						(cb), (arg),		\
						struct zcored *,	\
						const struct zcore_tx_output*), \
			    (arg))

void zcored_gettxout(struct zcored *zcored,
		       const struct zcore_txid *txid, const u32 outnum,
		       void (*cb)(struct zcored *zcored,
				  const struct zcore_tx_output *txout,
				  void *arg),
		       void *arg);

void zcored_getclientversion(struct zcored *zcored);

#endif /* LIGHTNING_LIGHTNINGD_ZCORED_H */
