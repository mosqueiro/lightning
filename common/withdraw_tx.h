#ifndef LIGHTNING_COMMON_WITHDRAW_TX_H
#define LIGHTNING_COMMON_WITHDRAW_TX_H
#include "config.h"
#include <zcore/chainparams.h>
#include <zcore/tx.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <common/amount.h>

struct zcore_tx;
struct ext_key;
struct privkey;
struct pubkey;
struct zcore_address;
struct utxo;

/**
 * withdraw_tx - Create a p2pkh withdrawal transaction
 *
 * @ctx: context to tal from.
 * @chainparams: (in) the params for the created transaction.
 * @utxos: (in/out) tal_arr of UTXO pointers to spend (permuted to match)
 * @outputs: (in) tal_arr of zcore_tx_output, scriptPubKeys with amount to send to.
 * @changekey: (in) key to send change to (only used if change_satoshis != 0).
 * @change: (in) amount to send as change.
 * @bip32_base: (in) bip32 base for key derivation, or NULL.
 * @change_outnum: (out) set to output index of change output or -1 if none, unless NULL.
 */
struct zcore_tx *withdraw_tx(const tal_t *ctx,
			       const struct chainparams *chainparams,
			       const struct utxo **utxos,
			       struct zcore_tx_output **outputs,
			       const struct pubkey *changekey,
			       struct amount_sat change,
			       const struct ext_key *bip32_base,
			       int *change_outnum);

#endif /* LIGHTNING_COMMON_WITHDRAW_TX_H */
