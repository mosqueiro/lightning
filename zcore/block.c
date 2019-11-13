#include "zcore/block.h"
#include "zcore/pullpush.h"
#include "zcore/tx.h"
#include <ccan/str/hex/hex.h>
#include <common/type_to_string.h>

/* Encoding is <blockhdr> <varint-num-txs> <tx>... */
struct zcore_block *
zcore_block_from_hex(const tal_t *ctx, const struct chainparams *chainparams,
		       const char *hex, size_t hexlen)
{
	struct zcore_block *b;
	u8 *linear_tx;
	const u8 *p;
	size_t len, i, num;

	if (hexlen && hex[hexlen-1] == '\n')
		hexlen--;

	/* Set up the block for success. */
	b = tal(ctx, struct zcore_block);

	/* De-hex the array. */
	len = hex_data_size(hexlen);
	p = linear_tx = tal_arr(ctx, u8, len);
	if (!hex_decode(hex, hexlen, linear_tx, len))
		return tal_free(b);

	b->hdr.version = pull_le32(&p, &len);
	pull(&p, &len, &b->hdr.prev_hash, sizeof(b->hdr.prev_hash));
	pull(&p, &len, &b->hdr.merkle_hash, sizeof(b->hdr.merkle_hash));
	b->hdr.timestamp = pull_le32(&p, &len);

	if (is_elements(chainparams)) {
		b->elements_hdr = tal(b, struct elements_block_hdr);
		b->elements_hdr->block_height = pull_le32(&p, &len);

		size_t challenge_len = pull_varint(&p, &len);
		b->elements_hdr->proof.challenge = tal_arr(b->elements_hdr, u8, challenge_len);
		pull(&p, &len, b->elements_hdr->proof.challenge, challenge_len);

		size_t solution_len = pull_varint(&p, &len);
		b->elements_hdr->proof.solution = tal_arr(b->elements_hdr, u8, solution_len);
		pull(&p, &len, b->elements_hdr->proof.solution, solution_len);

	} else {
		b->hdr.target = pull_le32(&p, &len);
		b->hdr.nonce = pull_le32(&p, &len);
	}

	num = pull_varint(&p, &len);
	b->tx = tal_arr(b, struct zcore_tx *, num);
	for (i = 0; i < num; i++) {
		b->tx[i] = pull_zcore_tx(b->tx, &p, &len);
		b->tx[i]->chainparams = chainparams;
	}

	/* We should end up not overrunning, nor have extra */
	if (!p || len)
		return tal_free(b);

	tal_free(linear_tx);
	return b;
}

void zcore_block_blkid(const struct zcore_block *b,
			 struct zcore_blkid *out)
{
	struct sha256_ctx shactx;
	u8 vt[VARINT_MAX_LEN];
	size_t vtlen;

	sha256_init(&shactx);
	sha256_le32(&shactx, b->hdr.version);
	sha256_update(&shactx, &b->hdr.prev_hash, sizeof(b->hdr.prev_hash));
	sha256_update(&shactx, &b->hdr.merkle_hash, sizeof(b->hdr.merkle_hash));
	sha256_le32(&shactx, b->hdr.timestamp);

        if (is_elements(chainparams)) {
		size_t clen = tal_bytelen(b->elements_hdr->proof.challenge);
		sha256_le32(&shactx, b->elements_hdr->block_height);

		vtlen = varint_put(vt, clen);
		sha256_update(&shactx, vt, vtlen);
		sha256_update(&shactx, b->elements_hdr->proof.challenge, clen);
		/* The solution is skipped, since that'd create a circular
		 * dependency apparently */
	} else {
		sha256_le32(&shactx, b->hdr.target);
		sha256_le32(&shactx, b->hdr.nonce);
	}
	sha256_double_done(&shactx, &out->shad);
}

/* We do the same hex-reversing crud as txids. */
bool zcore_blkid_from_hex(const char *hexstr, size_t hexstr_len,
			    struct zcore_blkid *blockid)
{
	struct zcore_txid fake_txid;
	if (!zcore_txid_from_hex(hexstr, hexstr_len, &fake_txid))
		return false;
	blockid->shad = fake_txid.shad;
	return true;
}

bool zcore_blkid_to_hex(const struct zcore_blkid *blockid,
			  char *hexstr, size_t hexstr_len)
{
	struct zcore_txid fake_txid;
	fake_txid.shad = blockid->shad;
	return zcore_txid_to_hex(&fake_txid, hexstr, hexstr_len);
}

static char *fmt_zcore_blkid(const tal_t *ctx,
			       const struct zcore_blkid *blkid)
{
	char *hexstr = tal_arr(ctx, char, hex_str_size(sizeof(*blkid)));

	zcore_blkid_to_hex(blkid, hexstr, hex_str_size(sizeof(*blkid)));
	return hexstr;
}
REGISTER_TYPE_TO_STRING(zcore_blkid, fmt_zcore_blkid);
