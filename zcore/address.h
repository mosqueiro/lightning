#ifndef LIGHTNING_ZCORE_ADDRESS_H
#define LIGHTNING_ZCORE_ADDRESS_H
#include "config.h"
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/short_types/short_types.h>

/* An address is the RIPEMD160 of the SHA of the public key. */
struct zcore_address {
	struct ripemd160 addr;
};
#endif /* LIGHTNING_ZCORE_ADDRESS_H */
