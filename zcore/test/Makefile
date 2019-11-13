ZCORE_TEST_SRC := $(wildcard zcore/test/run-*.c)
ZCORE_TEST_OBJS := $(ZCORE_TEST_SRC:.c=.o)
ZCORE_TEST_PROGRAMS := $(ZCORE_TEST_OBJS:.o=)

ZCORE_TEST_COMMON_OBJS := common/utils.o

$(ZCORE_TEST_PROGRAMS): $(CCAN_OBJS) $(ZCORE_TEST_COMMON_OBJS) zcore/chainparams.o
$(ZCORE_TEST_OBJS): $(CCAN_HEADERS) $(ZCORE_HEADERS) $(ZCORE_SRC)

ALL_TEST_PROGRAMS += $(ZCORE_TEST_PROGRAMS)
ALL_OBJS += $(ZCORE_TEST_PROGRAMS:=.o)

# This needs to know what level of optimization we're using.
zcore/test/run-secret_eq_consttime.o: CFLAGS += -DCOPTFLAGS="\"${COPTFLAGS}\""
update-mocks: $(ZCORE_TEST_SRC:%=update-mocks/%)

check-units: $(ZCORE_TEST_PROGRAMS:%=unittest/%)
