#include "zcore/script.h"
#include "zcore/tx.h"
#include "close_tx.h"
#include "permute_tx.h"
#include <assert.h>

struct zcore_tx *create_close_tx(const tal_t *ctx,
				   const struct chainparams *chainparams,
				   const u8 *our_script,
				   const u8 *their_script,
				   const struct zcore_txid *anchor_txid,
				   unsigned int anchor_index,
				   struct amount_sat funding,
				   struct amount_sat to_us,
				   struct amount_sat to_them,
				   struct amount_sat dust_limit)
{
	struct zcore_tx *tx;
	size_t num_outputs = 0;
	struct amount_sat total_out;
	u8 *script;

	assert(amount_sat_add(&total_out, to_us, to_them));
	assert(amount_sat_less_eq(total_out, funding));

	/* BOLT #3:
	 *
	 * ## Closing Transaction
	 *
	 * Note that there are two possible variants for each node.
	 *
	 * * version: 2
	 * * locktime: 0
	 * * txin count: 1
	 */
	/* Now create close tx: one input, two outputs. */
	tx = zcore_tx(ctx, chainparams, 1, 2);

	/* Our input spends the anchor tx output. */
	zcore_tx_add_input(tx, anchor_txid, anchor_index,
			     ZCORE_TX_DEFAULT_SEQUENCE, funding, NULL);

	if (amount_sat_greater_eq(to_us, dust_limit)) {
		script =
		    tal_dup_arr(tx, u8, our_script, tal_count(our_script), 0);
		/* One output is to us. */
		zcore_tx_add_output(tx, script, to_us);
		num_outputs++;
	}

	if (amount_sat_greater_eq(to_them, dust_limit)) {
		script = tal_dup_arr(tx, u8, their_script,
				     tal_count(their_script), 0);
		/* Other output is to them. */
		zcore_tx_add_output(tx, script, to_them);
		num_outputs++;
	}

	/* Can't have no outputs at all! */
	if (num_outputs == 0)
		return tal_free(tx);

	permute_outputs(tx, NULL, NULL);
	elements_tx_add_fee_output(tx);

	assert(zcore_tx_check(tx));
	return tx;
}
