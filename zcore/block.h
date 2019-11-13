#ifndef LIGHTNING_ZCORE_BLOCK_H
#define LIGHTNING_ZCORE_BLOCK_H
#include "config.h"
#include "zcore/shadouble.h"
#include <ccan/endian/endian.h>
#include <ccan/short_types/short_types.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/tal.h>
#include <stdbool.h>

struct chainparams;

struct zcore_blkid {
	struct sha256_double shad;
};
/* Define zcore_blkid_eq (no padding) */
STRUCTEQ_DEF(zcore_blkid, 0, shad.sha.u);

struct zcore_block_hdr {
	le32 version;
	struct zcore_blkid prev_hash;
	struct sha256_double merkle_hash;
	le32 timestamp;
	le32 target;
	le32 nonce;
};

struct elements_block_proof {
	u8 *challenge;
	u8 *solution;
};

struct elements_block_hdr {
	u32 block_height;
	struct elements_block_proof proof;
};

struct zcore_block {
	struct zcore_block_hdr hdr;
	struct elements_block_hdr *elements_hdr;
	/* tal_count shows now many */
	struct zcore_tx **tx;
};

struct zcore_block *
zcore_block_from_hex(const tal_t *ctx, const struct chainparams *chainparams,
		       const char *hex, size_t hexlen);

/* Compute the double SHA block ID from the block header. */
void zcore_block_blkid(const struct zcore_block *block,
			 struct zcore_blkid *out);

/* Parse hex string to get blockid (reversed, a-la zcored). */
bool zcore_blkid_from_hex(const char *hexstr, size_t hexstr_len,
			    struct zcore_blkid *blockid);

/* Get hex string of blockid (reversed, a-la zcored). */
bool zcore_blkid_to_hex(const struct zcore_blkid *blockid,
			  char *hexstr, size_t hexstr_len);
#endif /* LIGHTNING_ZCORE_BLOCK_H */
