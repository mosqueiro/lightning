#ifndef LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H
#define LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <lightningd/lightningd.h>
#include <onchaind/gen_onchain_wire.h>

struct channel;
struct zcore_tx;
struct block;

enum watch_result onchaind_funding_spent(struct channel *channel,
					 const struct zcore_tx *tx,
					 u32 blockheight);

void onchaind_replay_channels(struct lightningd *ld);

#endif /* LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H */
