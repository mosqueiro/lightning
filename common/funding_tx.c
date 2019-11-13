#include "funding_tx.h"
#include <assert.h>
#include <zcore/pubkey.h>
#include <zcore/script.h>
#include <zcore/tx.h>
#include <ccan/ptrint/ptrint.h>
#include <common/permute_tx.h>
#include <common/utxo.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

struct zcore_tx *funding_tx(const tal_t *ctx,
			      const struct chainparams *chainparams,
			      u16 *outnum,
			      const struct utxo **utxomap,
			      struct amount_sat funding,
			      const struct pubkey *local_fundingkey,
			      const struct pubkey *remote_fundingkey,
			      struct amount_sat change,
			      const struct pubkey *changekey,
			      const struct ext_key *bip32_base)
{
	u8 *wscript;
	struct zcore_tx *tx;
	bool has_change = !amount_sat_eq(change, AMOUNT_SAT(0));

	tx = tx_spending_utxos(ctx, chainparams, utxomap, bip32_base, has_change, 1);


	wscript = zcore_redeem_2of2(tx, local_fundingkey, remote_fundingkey);
	SUPERVERBOSE("# funding witness script = %s\n",
		     tal_hex(wscript, wscript));
	zcore_tx_add_output(tx, scriptpubkey_p2wsh(tx, wscript), funding);
	tal_free(wscript);

	if (has_change) {
		const void *map[2];
		map[0] = int2ptr(0);
		map[1] = int2ptr(1);
		zcore_tx_add_output(tx, scriptpubkey_p2wpkh(tx, changekey),
				      change);
		permute_outputs(tx, NULL, map);
		*outnum = (map[0] == int2ptr(0) ? 0 : 1);
	} else {
		*outnum = 0;
	}

	permute_inputs(tx, (const void **)utxomap);

	elements_tx_add_fee_output(tx);
	assert(zcore_tx_check(tx));
	return tx;
}
