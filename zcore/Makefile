# Included for one dir up.

ZCORE_SRC :=					\
	zcore/base58.c			\
	zcore/block.c				\
	zcore/chainparams.c			\
	zcore/locktime.c			\
	zcore/privkey.c			\
	zcore/pubkey.c			\
	zcore/pullpush.c			\
	zcore/script.c			\
	zcore/shadouble.c			\
	zcore/short_channel_id.c		\
	zcore/signature.c			\
	zcore/tx.c				\
	zcore/varint.c

ZCORE_OBJS := $(ZCORE_SRC:.c=.o)

ZCORE_HEADERS := zcore/address.h		\
	zcore/base58.h			\
	zcore/block.h				\
	zcore/chainparams.h			\
	zcore/feerate.h			\
	zcore/locktime.h			\
	zcore/preimage.h			\
	zcore/privkey.h			\
	zcore/pubkey.h			\
	zcore/pullpush.h			\
	zcore/script.h			\
	zcore/shadouble.h			\
	zcore/short_channel_id.h		\
	zcore/signature.h			\
	zcore/tx.h				\
	zcore/varint.h

check-source: $(ZCORE_SRC:%=check-src-include-order/%)		\
	$(ZCORE_HEADERS:%=check-hdr-include-order/%)

# ZCore objects depends on zcore/ external/ and ccan
$(ZCORE_OBJS): $(CCAN_HEADERS) $(ZCORE_HEADERS) $(EXTERNAL_HEADERS)

check-source-bolt: $(ZCORE_SRC:%=bolt-check/%) $(ZCORE_HEADERS:%=bolt-check/%)

check-makefile: check-zcore-makefile

check-zcore-makefile:
	@if [ "`echo zcore/*.h`" != "$(ZCORE_HEADERS)" ]; then echo ZCORE_HEADERS incorrect; exit 1; fi

check-whitespace: $(ZCORE_SRC:%=check-whitespace/%) $(ZCORE_HEADERS:%=check-whitespace/%) check-whitespace/zcore/Makefile

clean: zcore-clean

zcore-clean:
	$(RM) $(ZCORE_OBJS) $(ZCORE_TEST_PROGRAMS) $(ZCORE_TEST_OBJS)

include zcore/test/Makefile
