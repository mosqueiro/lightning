#ifndef LIGHTNING_COMMON_PERMUTE_TX_H
#define LIGHTNING_COMMON_PERMUTE_TX_H
#include "config.h"
#include "zcore/tx.h"

struct htlc;

/**
 * permute_inputs: permute the transaction inputs into BIP69 order.
 * @tx: the transaction whose inputs are to be sorted (inputs must be tal_arr).
 * @map: if non-NULL, pointers to be permuted the same as the inputs.
 */
void permute_inputs(struct zcore_tx *tx, const void **map);

/**
 * permute_outputs: permute the transaction outputs into BIP69 + cltv order.
 * @tx: the transaction whose outputs are to be sorted (outputs must be tal_arr).
 * @cltvs: CLTV delays to use as a tie-breaker, or NULL.
 * @map: if non-NULL, pointers to be permuted the same as the outputs.
 *
 * So the caller initiates the map with which htlcs are used, it
 * can easily see which htlc (if any) is in output #0 with map[0].
 */
void permute_outputs(struct zcore_tx *tx, u32 *cltvs, const void **map);
#endif /* LIGHTNING_COMMON_PERMUTE_TX_H */
