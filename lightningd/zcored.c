/* Code for talking to zcored.  We use zcore-cli. */
#include "zcore/base58.h"
#include "zcore/block.h"
#include "zcore/feerate.h"
#include "zcore/script.h"
#include "zcore/shadouble.h"
#include "zcored.h"
#include "lightningd.h"
#include "log.h"
#include <ccan/cast/cast.h>
#include <ccan/io/io.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/str/hex/hex.h>
#include <ccan/take/take.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/json_helpers.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <common/utils.h>
#include <errno.h>
#include <inttypes.h>
#include <lightningd/chaintopology.h>

/* ZCored's web server has a default of 4 threads, with queue depth 16.
 * It will *fail* rather than queue beyond that, so we must not stress it!
 *
 * This is how many request for each priority level we have.
 */
#define ZCORED_MAX_PARALLEL 4

/* Add the n'th arg to *args, incrementing n and keeping args of size n+1 */
static void add_arg(const char ***args, const char *arg)
{
	tal_arr_expand(args, arg);
}

static const char **gather_args(const struct zcored *zcored,
				const tal_t *ctx, const char *cmd, va_list ap)
{
	const char **args = tal_arr(ctx, const char *, 1);
	const char *arg;

	args[0] = zcored->cli ? zcored->cli : zcored->chainparams->cli;
	if (zcored->chainparams->cli_args)
		add_arg(&args, zcored->chainparams->cli_args);

	if (zcored->datadir)
		add_arg(&args, tal_fmt(args, "-datadir=%s", zcored->datadir));


	if (zcored->rpcconnect)
		add_arg(&args,
			tal_fmt(args, "-rpcconnect=%s", zcored->rpcconnect));

	if (zcored->rpcport)
		add_arg(&args,
			tal_fmt(args, "-rpcport=%s", zcored->rpcport));

	if (zcored->rpcuser)
		add_arg(&args, tal_fmt(args, "-rpcuser=%s", zcored->rpcuser));

	if (zcored->rpcpass)
		add_arg(&args,
			tal_fmt(args, "-rpcpassword=%s", zcored->rpcpass));

	add_arg(&args, cmd);

	while ((arg = va_arg(ap, const char *)) != NULL)
		add_arg(&args, tal_strdup(args, arg));

	add_arg(&args, NULL);
	return args;
}

struct zcore_cli {
	struct list_node list;
	struct zcored *zcored;
	int fd;
	int *exitstatus;
	pid_t pid;
	const char **args;
	struct timeabs start;
	enum zcored_prio prio;
	char *output;
	size_t output_bytes;
	size_t new_output;
	bool (*process)(struct zcore_cli *);
	void *cb;
	void *cb_arg;
	struct zcore_cli **stopper;
};

static struct io_plan *read_more(struct io_conn *conn, struct zcore_cli *bcli)
{
	bcli->output_bytes += bcli->new_output;
	if (bcli->output_bytes == tal_count(bcli->output))
		tal_resize(&bcli->output, bcli->output_bytes * 2);
	return io_read_partial(conn, bcli->output + bcli->output_bytes,
			       tal_count(bcli->output) - bcli->output_bytes,
			       &bcli->new_output, read_more, bcli);
}

static struct io_plan *output_init(struct io_conn *conn, struct zcore_cli *bcli)
{
	bcli->output_bytes = bcli->new_output = 0;
	bcli->output = tal_arr(bcli, char, 100);
	return read_more(conn, bcli);
}

static void next_bcli(struct zcored *zcored, enum zcored_prio prio);

/* For printing: simple string of args (no secrets!) */
static char *args_string(const tal_t *ctx, const char **args)
{
	size_t i;
	char *ret = tal_strdup(ctx, args[0]);

	for (i = 1; args[i]; i++) {
            ret = tal_strcat(ctx, take(ret), " ");
            if (strstarts(args[i], "-rpcpassword")) {
                    ret = tal_strcat(ctx, take(ret), "-rpcpassword=...");
            } else if (strstarts(args[i], "-rpcuser")) {
                    ret = tal_strcat(ctx, take(ret), "-rpcuser=...");
            } else {
                ret = tal_strcat(ctx, take(ret), args[i]);
            }
	}
	return ret;
}

static char *bcli_args(const tal_t *ctx, struct zcore_cli *bcli)
{
    return args_string(ctx, bcli->args);
}

static void retry_bcli(struct zcore_cli *bcli)
{
	list_add_tail(&bcli->zcored->pending[bcli->prio], &bcli->list);
	next_bcli(bcli->zcored, bcli->prio);
}

/* We allow 60 seconds of spurious errors, eg. reorg. */
static void bcli_failure(struct zcored *zcored,
			 struct zcore_cli *bcli,
			 int exitstatus)
{
	struct timerel t;

	if (!zcored->error_count)
		zcored->first_error_time = time_mono();

	t = timemono_between(time_mono(), zcored->first_error_time);
	if (time_greater(t, time_from_sec(zcored->retry_timeout)))
		fatal("%s exited %u (after %u other errors) '%.*s'; "
		      "we have been retrying command for "
		      "--zcore-retry-timeout=%"PRIu64" seconds; "
		      "zcored setup or our --zcore-* configs broken?",
		      bcli_args(tmpctx, bcli),
		      exitstatus,
		      zcored->error_count,
		      (int)bcli->output_bytes,
		      bcli->output,
		      zcored->retry_timeout);

	log_unusual(zcored->log,
		    "%s exited with status %u",
		    bcli_args(tmpctx, bcli), exitstatus);

	zcored->error_count++;

	/* Retry in 1 second (not a leak!) */
	new_reltimer(zcored->ld->timers, notleak(bcli), time_from_sec(1),
		     retry_bcli, bcli);
}

static void bcli_finished(struct io_conn *conn UNUSED, struct zcore_cli *bcli)
{
	int ret, status;
	struct zcored *zcored = bcli->zcored;
	enum zcored_prio prio = bcli->prio;
	bool ok;
	u64 msec = time_to_msec(time_between(time_now(), bcli->start));

	/* If it took over 10 seconds, that's rather strange. */
	if (msec > 10000)
		log_unusual(zcored->log,
			    "zcore-cli: finished %s (%"PRIu64" ms)",
			    bcli_args(tmpctx, bcli), msec);

	assert(zcored->num_requests[prio] > 0);

	/* FIXME: If we waited for SIGCHILD, this could never hang! */
	while ((ret = waitpid(bcli->pid, &status, 0)) < 0 && errno == EINTR);
	if (ret != bcli->pid)
		fatal("%s %s", bcli_args(tmpctx, bcli),
		      ret == 0 ? "not exited?" : strerror(errno));

	if (!WIFEXITED(status))
		fatal("%s died with signal %i",
		      bcli_args(tmpctx, bcli),
		      WTERMSIG(status));

	if (!bcli->exitstatus) {
		if (WEXITSTATUS(status) != 0) {
			bcli_failure(zcored, bcli, WEXITSTATUS(status));
			zcored->num_requests[prio]--;
			goto done;
		}
	} else
		*bcli->exitstatus = WEXITSTATUS(status);

	if (WEXITSTATUS(status) == 0)
		zcored->error_count = 0;

	zcored->num_requests[bcli->prio]--;

	/* Don't continue if were only here because we were freed for shutdown */
	if (zcored->shutdown)
		return;

	db_begin_transaction(zcored->ld->wallet->db);
	ok = bcli->process(bcli);
	db_commit_transaction(zcored->ld->wallet->db);

	if (!ok)
		bcli_failure(zcored, bcli, WEXITSTATUS(status));
	else
		tal_free(bcli);

done:
	next_bcli(zcored, prio);
}

static void next_bcli(struct zcored *zcored, enum zcored_prio prio)
{
	struct zcore_cli *bcli;
	struct io_conn *conn;

	if (zcored->num_requests[prio] >= ZCORED_MAX_PARALLEL)
		return;

	bcli = list_pop(&zcored->pending[prio], struct zcore_cli, list);
	if (!bcli)
		return;

	bcli->pid = pipecmdarr(NULL, &bcli->fd, &bcli->fd,
			       cast_const2(char **, bcli->args));
	if (bcli->pid < 0)
		fatal("%s exec failed: %s", bcli->args[0], strerror(errno));

	bcli->start = time_now();

	zcored->num_requests[prio]++;

	/* This lifetime is attached to zcored command fd */
	conn = notleak(io_new_conn(zcored, bcli->fd, output_init, bcli));
	io_set_finish(conn, bcli_finished, bcli);
}

static bool process_donothing(struct zcore_cli *bcli UNUSED)
{
	return true;
}

/* If stopper gets freed first, set process() to a noop. */
static void stop_process_bcli(struct zcore_cli **stopper)
{
	(*stopper)->process = process_donothing;
	(*stopper)->stopper = NULL;
}

/* It command finishes first, free stopper. */
static void remove_stopper(struct zcore_cli *bcli)
{
	/* Calls stop_process_bcli, but we don't care. */
	tal_free(bcli->stopper);
}

/* If ctx is non-NULL, and is freed before we return, we don't call process().
 * process returns false() if it's a spurious error, and we should retry. */
static void
start_zcore_cli(struct zcored *zcored,
		  const tal_t *ctx,
		  bool (*process)(struct zcore_cli *),
		  bool nonzero_exit_ok,
		  enum zcored_prio prio,
		  void *cb, void *cb_arg,
		  char *cmd, ...)
{
	va_list ap;
	struct zcore_cli *bcli = tal(zcored, struct zcore_cli);

	bcli->zcored = zcored;
	bcli->process = process;
	bcli->prio = prio;
	bcli->cb = cb;
	bcli->cb_arg = cb_arg;
	if (ctx) {
		/* Create child whose destructor will stop us calling */
		bcli->stopper = tal(ctx, struct zcore_cli *);
		*bcli->stopper = bcli;
		tal_add_destructor(bcli->stopper, stop_process_bcli);
		tal_add_destructor(bcli, remove_stopper);
	} else
		bcli->stopper = NULL;

	if (nonzero_exit_ok)
		bcli->exitstatus = tal(bcli, int);
	else
		bcli->exitstatus = NULL;
	va_start(ap, cmd);
	bcli->args = gather_args(zcored, bcli, cmd, ap);
	va_end(ap);

	list_add_tail(&zcored->pending[bcli->prio], &bcli->list);
	next_bcli(zcored, bcli->prio);
}

static bool extract_feerate(struct zcore_cli *bcli,
			    const char *output, size_t output_bytes,
			    u64 *feerate)
{
	const jsmntok_t *tokens, *feeratetok;
	bool valid;

	tokens = json_parse_input(output, output, output_bytes, &valid);
	if (!tokens)
		fatal("%s: %s response",
		      bcli_args(tmpctx, bcli),
		      valid ? "partial" : "invalid");

	if (tokens[0].type != JSMN_OBJECT) {
		log_unusual(bcli->zcored->log,
			    "%s: gave non-object (%.*s)?",
			    bcli_args(tmpctx, bcli),
			    (int)output_bytes, output);
		return false;
	}

	feeratetok = json_get_member(output, tokens, "feerate");
	if (!feeratetok)
		return false;

	return json_to_zcore_amount(output, feeratetok, feerate);
}

struct estimatefee {
	size_t i;
	const u32 *blocks;
	const char **estmode;

	void (*cb)(struct zcored *zcored, const u32 satoshi_per_kw[],
		   void *);
	void *arg;
	u32 *satoshi_per_kw;
};

static void do_one_estimatefee(struct zcored *zcored,
			       struct estimatefee *efee);

static bool process_estimatefee(struct zcore_cli *bcli)
{
	u64 feerate;
	struct estimatefee *efee = bcli->cb_arg;

	/* FIXME: We could trawl recent blocks for median fee... */
	if (!extract_feerate(bcli, bcli->output, bcli->output_bytes, &feerate)) {
		log_unusual(bcli->zcored->log, "Unable to estimate %s/%u fee",
			    efee->estmode[efee->i], efee->blocks[efee->i]);

#if DEVELOPER
		/* This is needed to test for failed feerate estimates
		 * in DEVELOPER mode */
		efee->satoshi_per_kw[efee->i] = 0;
#else
		/* If we are in testnet mode we want to allow payments
		 * with the minimal fee even if the estimate didn't
		 * work out. This is less disruptive than erring out
		 * all the time. */
		if (get_chainparams(bcli->zcored->ld)->testnet)
			efee->satoshi_per_kw[efee->i] = FEERATE_FLOOR;
		else
			efee->satoshi_per_kw[efee->i] = 0;
#endif
	} else
		/* Rate in satoshi per kw. */
		efee->satoshi_per_kw[efee->i]
			= feerate_from_style(feerate, FEERATE_PER_KBYTE);

	efee->i++;
	if (efee->i == tal_count(efee->satoshi_per_kw)) {
		efee->cb(bcli->zcored, efee->satoshi_per_kw, efee->arg);
		tal_free(efee);
	} else {
		/* Next */
		do_one_estimatefee(bcli->zcored, efee);
	}
	return true;
}

static void do_one_estimatefee(struct zcored *zcored,
			       struct estimatefee *efee)
{
	char blockstr[STR_MAX_CHARS(u32)];

	snprintf(blockstr, sizeof(blockstr), "%u", efee->blocks[efee->i]);
	start_zcore_cli(zcored, NULL, process_estimatefee, false,
			  ZCORED_LOW_PRIO,
			  NULL, efee,
			  "estimatesmartfee", blockstr, efee->estmode[efee->i],
			  NULL);
}

void zcored_estimate_fees_(struct zcored *zcored,
			     const u32 blocks[], const char *estmode[],
			     size_t num_estimates,
			     void (*cb)(struct zcored *zcored,
					const u32 satoshi_per_kw[], void *),
			     void *arg)
{
	struct estimatefee *efee = tal(zcored, struct estimatefee);

	efee->i = 0;
	efee->blocks = tal_dup_arr(efee, u32, blocks, num_estimates, 0);
	efee->estmode = tal_dup_arr(efee, const char *, estmode, num_estimates,
				    0);
	efee->cb = cb;
	efee->arg = arg;
	efee->satoshi_per_kw = tal_arr(efee, u32, num_estimates);

	do_one_estimatefee(zcored, efee);
}

static bool process_sendrawtx(struct zcore_cli *bcli)
{
	void (*cb)(struct zcored *zcored,
		   int, const char *msg, void *) = bcli->cb;
	const char *msg = tal_strndup(bcli, bcli->output,
				      bcli->output_bytes);

	log_debug(bcli->zcored->log, "sendrawtx exit %u, gave %s",
		  *bcli->exitstatus, msg);

	cb(bcli->zcored, *bcli->exitstatus, msg, bcli->cb_arg);
	return true;
}

void zcored_sendrawtx_(struct zcored *zcored,
			 const char *hextx,
			 void (*cb)(struct zcored *zcored,
				    int exitstatus, const char *msg, void *),
			 void *arg)
{
	log_debug(zcored->log, "sendrawtransaction: %s", hextx);
	start_zcore_cli(zcored, NULL, process_sendrawtx, true,
			  ZCORED_HIGH_PRIO,
			  cb, arg,
			  "sendrawtransaction", hextx, NULL);
}

static bool process_rawblock(struct zcore_cli *bcli)
{
	struct zcore_block *blk;
	void (*cb)(struct zcored *zcored,
		   struct zcore_block *blk,
		   void *arg) = bcli->cb;

	blk = zcore_block_from_hex(bcli, bcli->zcored->chainparams,
				     bcli->output, bcli->output_bytes);
	if (!blk)
		fatal("%s: bad block '%.*s'?",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes, bcli->output);

	cb(bcli->zcored, blk, bcli->cb_arg);
	return true;
}

void zcored_getrawblock_(struct zcored *zcored,
			   const struct zcore_blkid *blockid,
			   void (*cb)(struct zcored *zcored,
				      struct zcore_block *blk,
				      void *arg),
			   void *arg)
{
	char hex[hex_str_size(sizeof(*blockid))];

	zcore_blkid_to_hex(blockid, hex, sizeof(hex));
	start_zcore_cli(zcored, NULL, process_rawblock, false,
			  ZCORED_HIGH_PRIO,
			  cb, arg,
			  "getblock", hex, "false", NULL);
}

static bool process_getblockcount(struct zcore_cli *bcli)
{
	u32 blockcount;
	char *p, *end;
	void (*cb)(struct zcored *zcored,
		   u32 blockcount,
		   void *arg) = bcli->cb;

	p = tal_strndup(bcli, bcli->output, bcli->output_bytes);
	blockcount = strtol(p, &end, 10);
	if (end == p || *end != '\n')
		fatal("%s: gave non-numeric blockcount %s",
		      bcli_args(tmpctx, bcli), p);

	cb(bcli->zcored, blockcount, bcli->cb_arg);
	return true;
}

void zcored_getblockcount_(struct zcored *zcored,
			      void (*cb)(struct zcored *zcored,
					 u32 blockcount,
					 void *arg),
			      void *arg)
{
	start_zcore_cli(zcored, NULL, process_getblockcount, false,
			  ZCORED_HIGH_PRIO,
			  cb, arg,
			  "getblockcount", NULL);
}

struct get_output {
	unsigned int blocknum, txnum, outnum;

	/* The real callback */
	void (*cb)(struct zcored *zcored, const struct zcore_tx_output *txout, void *arg);

	/* The real callback arg */
	void *cbarg;
};

static void process_get_output(struct zcored *zcored, const struct zcore_tx_output *txout, void *arg)
{
	struct get_output *go = arg;
	go->cb(zcored, txout, go->cbarg);
}

static bool process_gettxout(struct zcore_cli *bcli)
{
	void (*cb)(struct zcored *zcored,
		   const struct zcore_tx_output *output,
		   void *arg) = bcli->cb;
	const jsmntok_t *tokens, *valuetok, *scriptpubkeytok, *hextok;
	struct zcore_tx_output out;
	bool valid;

	/* As of at least v0.15.1.0, zcored returns "success" but an empty
	   string on a spent gettxout */
	if (*bcli->exitstatus != 0 || bcli->output_bytes == 0) {
		cb(bcli->zcored, NULL, bcli->cb_arg);
		return true;
	}

	tokens = json_parse_input(bcli->output, bcli->output, bcli->output_bytes,
				  &valid);
	if (!tokens)
		fatal("%s: %s response",
		      bcli_args(tmpctx, bcli), valid ? "partial" : "invalid");

	if (tokens[0].type != JSMN_OBJECT)
		fatal("%s: gave non-object (%.*s)?",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes, bcli->output);

	valuetok = json_get_member(bcli->output, tokens, "value");
	if (!valuetok)
		fatal("%s: had no value member (%.*s)?",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes, bcli->output);

	if (!json_to_zcore_amount(bcli->output, valuetok, &out.amount.satoshis)) /* Raw: talking to zcored */
		fatal("%s: had bad value (%.*s)?",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes, bcli->output);

	scriptpubkeytok = json_get_member(bcli->output, tokens, "scriptPubKey");
	if (!scriptpubkeytok)
		fatal("%s: had no scriptPubKey member (%.*s)?",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes, bcli->output);
	hextok = json_get_member(bcli->output, scriptpubkeytok, "hex");
	if (!hextok)
		fatal("%s: had no scriptPubKey->hex member (%.*s)?",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes, bcli->output);

	out.script = tal_hexdata(bcli, bcli->output + hextok->start,
				 hextok->end - hextok->start);
	if (!out.script)
		fatal("%s: scriptPubKey->hex invalid hex (%.*s)?",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes, bcli->output);

	cb(bcli->zcored, &out, bcli->cb_arg);
	return true;
}

/**
 * process_getblock -- Retrieve a block from zcored
 *
 * Used to resolve a `txoutput` after identifying the blockhash, and
 * before extracting the outpoint from the UTXO.
 */
static bool process_getblock(struct zcore_cli *bcli)
{
	void (*cb)(struct zcored *zcored,
		   const struct zcore_tx_output *output,
		   void *arg) = bcli->cb;
	struct get_output *go = bcli->cb_arg;
	void *cbarg = go->cbarg;
	const jsmntok_t *tokens, *txstok, *txidtok;
	struct zcore_txid txid;
	bool valid;

	tokens = json_parse_input(bcli->output, bcli->output, bcli->output_bytes,
				  &valid);
	if (!tokens) {
		/* Most likely we are running on a pruned node, call
		 * the callback with NULL to indicate failure */
		log_debug(bcli->zcored->log,
			  "%s: returned invalid block, is this a pruned node?",
			  bcli_args(tmpctx, bcli));
		cb(bcli->zcored, NULL, cbarg);
		tal_free(go);
		return true;
	}

	if (tokens[0].type != JSMN_OBJECT)
		fatal("%s: gave non-object (%.*s)?",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes, bcli->output);

	/*  "tx": [
	    "1a7bb0f58a5d235d232deb61d9e2208dabe69848883677abe78e9291a00638e8",
	    "56a7e3468c16a4e21a4722370b41f522ad9dd8006c0e4e73c7d1c47f80eced94",
	    ...
	*/
	txstok = json_get_member(bcli->output, tokens, "tx");
	if (!txstok)
		fatal("%s: had no tx member (%.*s)?",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes, bcli->output);

	/* Now, this can certainly happen, if txnum too large. */
	txidtok = json_get_arr(txstok, go->txnum);
	if (!txidtok) {
		log_debug(bcli->zcored->log, "%s: no txnum %u",
			  bcli_args(tmpctx, bcli), go->txnum);
		cb(bcli->zcored, NULL, cbarg);
		tal_free(go);
		return true;
	}

	if (!zcore_txid_from_hex(bcli->output + txidtok->start,
				   txidtok->end - txidtok->start,
				   &txid))
		fatal("%s: had bad txid (%.*s)?",
		      bcli_args(tmpctx, bcli),
		      json_tok_full_len(txidtok),
		      json_tok_full(bcli->output, txidtok));

	go->cb = cb;
	/* Now get the raw tx output. */
	zcored_gettxout(bcli->zcored, &txid, go->outnum, process_get_output, go);
	return true;
}

static bool process_getblockhash_for_txout(struct zcore_cli *bcli)
{
	void (*cb)(struct zcored *zcored,
		   const struct zcore_tx_output *output,
		   void *arg) = bcli->cb;
	struct get_output *go = bcli->cb_arg;
	char *blockhash;

	if (*bcli->exitstatus != 0) {
		void *cbarg = go->cbarg;
		log_debug(bcli->zcored->log, "%s: invalid blocknum?",
			  bcli_args(tmpctx, bcli));
		tal_free(go);
		cb(bcli->zcored, NULL, cbarg);
		return true;
	}

	/* Strip the newline at the end of the previous output */
	blockhash = tal_strndup(NULL, bcli->output, bcli->output_bytes-1);

	start_zcore_cli(bcli->zcored, NULL, process_getblock, true,
			  ZCORED_LOW_PRIO,
			  cb, go,
			  "getblock", take(blockhash), NULL);
	return true;
}

void zcored_getoutput_(struct zcored *zcored,
			 unsigned int blocknum, unsigned int txnum,
			 unsigned int outnum,
			 void (*cb)(struct zcored *zcored,
				    const struct zcore_tx_output *output,
				    void *arg),
			 void *arg)
{
	struct get_output *go = tal(zcored, struct get_output);
	go->blocknum = blocknum;
	go->txnum = txnum;
	go->outnum = outnum;
	go->cbarg = arg;

	/* We may not have topology ourselves that far back, so ask zcored */
	start_zcore_cli(zcored, NULL, process_getblockhash_for_txout,
			  true, ZCORED_LOW_PRIO, cb, go,
			  "getblockhash", take(tal_fmt(NULL, "%u", blocknum)),
			  NULL);

	/* Looks like a leak, but we free it in process_getblock */
	notleak(go);
}

static bool process_getblockhash(struct zcore_cli *bcli)
{
	struct zcore_blkid blkid;
	void (*cb)(struct zcored *zcored,
		   const struct zcore_blkid *blkid,
		   void *arg) = bcli->cb;

	/* If it failed with error 8, call with NULL block. */
	if (*bcli->exitstatus != 0) {
		/* Other error means we have to retry. */
		if (*bcli->exitstatus != 8)
			return false;
		cb(bcli->zcored, NULL, bcli->cb_arg);
		return true;
	}

	if (bcli->output_bytes == 0
	    || !zcore_blkid_from_hex(bcli->output, bcli->output_bytes-1,
				       &blkid)) {
		fatal("%s: bad blockid '%.*s'",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes, bcli->output);
	}

	cb(bcli->zcored, &blkid, bcli->cb_arg);
	return true;
}

void zcored_getblockhash_(struct zcored *zcored,
			    u32 height,
			    void (*cb)(struct zcored *zcored,
				       const struct zcore_blkid *blkid,
				       void *arg),
			    void *arg)
{
	char str[STR_MAX_CHARS(height)];
	snprintf(str, sizeof(str), "%u", height);

	start_zcore_cli(zcored, NULL, process_getblockhash, true,
			  ZCORED_HIGH_PRIO,
			  cb, arg,
			  "getblockhash", str, NULL);
}

void zcored_gettxout(struct zcored *zcored,
		       const struct zcore_txid *txid, const u32 outnum,
		       void (*cb)(struct zcored *zcored,
				  const struct zcore_tx_output *txout,
				  void *arg),
		       void *arg)
{
	start_zcore_cli(zcored, NULL,
			  process_gettxout, true, ZCORED_LOW_PRIO, cb, arg,
			  "gettxout",
			  take(type_to_string(NULL, struct zcore_txid, txid)),
			  take(tal_fmt(NULL, "%u", outnum)),
			  NULL);
}

/* Context for the getfilteredblock call. Wraps the actual arguments while we
 * process the various steps. */
struct filteredblock_call {
	struct list_node list;
	void (*cb)(struct zcored *zcored, const struct filteredblock *fb,
		   void *arg);
	void *arg;

	struct filteredblock *result;
	struct filteredblock_outpoint **outpoints;
	size_t current_outpoint;
	struct timeabs start_time;
	u32 height;
};

/* Declaration for recursion in process_getfilteredblock_step1 */
static void
process_getfiltered_block_final(struct zcored *zcored,
				const struct filteredblock_call *call);

static void
process_getfilteredblock_step3(struct zcored *zcored,
			       const struct zcore_tx_output *output,
			       void *arg)
{
	struct filteredblock_call *call = (struct filteredblock_call *)arg;
	struct filteredblock_outpoint *o = call->outpoints[call->current_outpoint];

	/* If this output is unspent, add it to the filteredblock result. */
	if (output)
		tal_arr_expand(&call->result->outpoints, tal_steal(call->result, o));

	call->current_outpoint++;
	if (call->current_outpoint < tal_count(call->outpoints)) {
		o = call->outpoints[call->current_outpoint];
		zcored_gettxout(zcored, &o->txid, o->outnum,
				  process_getfilteredblock_step3, call);
	} else {
		/* If there were no more outpoints to check, we call the callback. */
		process_getfiltered_block_final(zcored, call);
	}
}

static void process_getfilteredblock_step2(struct zcored *zcored,
					   struct zcore_block *block,
					   struct filteredblock_call *call)
{
	struct filteredblock_outpoint *o;
	struct zcore_tx *tx;

	/* If for some reason we couldn't get the block, just report a
	 * failure. */
	if (block == NULL)
		return process_getfiltered_block_final(zcored, call);

	call->result->prev_hash = block->hdr.prev_hash;

	/* Allocate an array containing all the potentially interesting
	 * outpoints. We will later copy the ones we're interested in into the
	 * call->result if they are unspent. */

	call->outpoints = tal_arr(call, struct filteredblock_outpoint *, 0);
	for (size_t i = 0; i < tal_count(block->tx); i++) {
		tx = block->tx[i];
		for (size_t j = 0; j < tx->wtx->num_outputs; j++) {
			const u8 *script = zcore_tx_output_get_script(NULL, tx, j);
			struct amount_asset amount = zcore_tx_output_get_amount(tx, j);
			if (amount_asset_is_main(&amount) && is_p2wsh(script, NULL)) {
				/* This is an interesting output, remember it. */
				o = tal(call->outpoints, struct filteredblock_outpoint);
				zcore_txid(tx, &o->txid);
				o->amount = amount_asset_to_sat(&amount);
				o->txindex = i;
				o->outnum = j;
				o->scriptPubKey = tal_steal(o, script);
				tal_arr_expand(&call->outpoints, o);
			} else {
				tal_free(script);
			}
		}
	}

	if (tal_count(call->outpoints) == 0) {
		/* If there were no outpoints to check, we can short-circuit
		 * and just call the callback. */
		process_getfiltered_block_final(zcored, call);
	} else {

		/* Otherwise we start iterating through call->outpoints and
		 * store the one's that are unspent in
		 * call->result->outpoints. */
		o = call->outpoints[call->current_outpoint];
		zcored_gettxout(zcored, &o->txid, o->outnum,
				  process_getfilteredblock_step3, call);
	}
}

static void process_getfilteredblock_step1(struct zcored *zcored,
					   const struct zcore_blkid *blkid,
					   struct filteredblock_call *call)
{
	/* If we were unable to fetch the block hash (zcored doesn't know
	 * about a block at that height), we can short-circuit and just call
	 * the callback. */
	if (!blkid)
		return process_getfiltered_block_final(zcored, call);

	/* So we have the first piece of the puzzle, the block hash */
	call->result = tal(call, struct filteredblock);
	call->result->height = call->height;
	call->result->outpoints = tal_arr(call->result, struct filteredblock_outpoint *, 0);
	call->result->id = *blkid;

	/* Now get the raw block to get all outpoints that were created in
	 * this block. */
	zcored_getrawblock(zcored, blkid, process_getfilteredblock_step2, call);
}

/* Takes a call, dispatches it to all queued requests that match the same
 * height, and then kicks off the next call. */
static void
process_getfiltered_block_final(struct zcored *zcored,
				const struct filteredblock_call *call)
{
	struct filteredblock_call *c, *next;
	u32 height = call->height;

	if (call->result == NULL)
		goto next;

	/* Need to steal so we don't accidentally free it while iterating through the list below. */
	struct filteredblock *fb = tal_steal(NULL, call->result);
	list_for_each_safe(&zcored->pending_getfilteredblock, c, next, list) {
		if (c->height == height) {
			c->cb(zcored, fb, c->arg);
			list_del(&c->list);
			tal_free(c);
		}
	}
	tal_free(fb);

next:
	/* Nothing to free here, since `*call` was already deleted during the
	 * iteration above. It was also removed from the list, so no need to
	 * pop here. */
	if (!list_empty(&zcored->pending_getfilteredblock)) {
		c = list_top(&zcored->pending_getfilteredblock, struct filteredblock_call, list);
		zcored_getblockhash(zcored, c->height, process_getfilteredblock_step1, c);
	}
}

void zcored_getfilteredblock_(struct zcored *zcored, u32 height,
				void (*cb)(struct zcored *zcored,
					   const struct filteredblock *fb,
					   void *arg),
				void *arg)
{
	/* Stash the call context for when we need to call the callback after
	 * all the zcored calls we need to perform. */
	struct filteredblock_call *call = tal(zcored, struct filteredblock_call);
	/* If this is the first request, we should start processing it. */
	bool start = list_empty(&zcored->pending_getfilteredblock);
	call->cb = cb;
	call->arg = arg;
	call->height = height;
	assert(call->cb != NULL);
	call->start_time = time_now();
	call->result = NULL;
	call->current_outpoint = 0;

	list_add_tail(&zcored->pending_getfilteredblock, &call->list);
	if (start)
		zcored_getblockhash(zcored, height, process_getfilteredblock_step1, call);
}

static bool extract_numeric_version(struct zcore_cli *bcli,
			    const char *output, size_t output_bytes,
			    u64 *version)
{
	const jsmntok_t *tokens, *versiontok;
	bool valid;

	tokens = json_parse_input(output, output, output_bytes, &valid);
	if (!tokens)
		fatal("%s: %s response",
		      bcli_args(tmpctx, bcli),
		      valid ? "partial" : "invalid");

	if (tokens[0].type != JSMN_OBJECT) {
		log_unusual(bcli->zcored->log,
			    "%s: gave non-object (%.*s)?",
			    bcli_args(tmpctx, bcli),
			    (int)output_bytes, output);
		return false;
	}

	versiontok = json_get_member(output, tokens, "version");
	if (!versiontok)
		return false;

	return json_to_u64(output, versiontok, version);
}

static bool process_getclientversion(struct zcore_cli *bcli)
{
	u64 version;
	u64 min_version = bcli->zcored->chainparams->cli_min_supported_version;

	if (!extract_numeric_version(bcli, bcli->output,
				     bcli->output_bytes,
				     &version)) {
		fatal("%s: Unable to getclientversion (%.*s)",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes,
		      bcli->output);
	}

	if (version < min_version)
		fatal("Unsupported zcored version? zcored version: %"PRIu64","
		      " supported minimum version: %"PRIu64"",
		      version, min_version);

	return true;
}

void zcored_getclientversion(struct zcored *zcored)
{
	/* `getnetworkinfo` was added in v0.14.0. The older version would
	 * return non-zero exitstatus. */
	start_zcore_cli(zcored, NULL, process_getclientversion, false,
			  ZCORED_HIGH_PRIO,
			  NULL, NULL,
			  "getnetworkinfo", NULL);
}

/* Mutual recursion */
static bool process_getblockchaininfo(struct zcore_cli *bcli);

static void retry_getblockchaininfo(struct zcored *zcored)
{
	assert(!zcored->synced);
	start_zcore_cli(zcored, NULL,
			  process_getblockchaininfo,
			  false, ZCORED_LOW_PRIO, NULL, NULL,
			  "getblockchaininfo", NULL);
}

/* Given JSON object from getblockchaininfo, are we synced?  Poll if not. */
static void is_zcored_synced_yet(struct zcored *zcored,
				   const char *output, size_t output_len,
				   const jsmntok_t *obj,
				   bool initial)
{
	const jsmntok_t *t;
	unsigned int headers, blocks;
	bool ibd;

	t = json_get_member(output, obj, "headers");
	if (!t || !json_to_number(output, t, &headers))
		fatal("Invalid 'headers' field in getblockchaininfo '%.*s'",
		      (int)output_len, output);

	t = json_get_member(output, obj, "blocks");
	if (!t || !json_to_number(output, t, &blocks))
		fatal("Invalid 'blocks' field in getblockchaininfo '%.*s'",
		      (int)output_len, output);

	t = json_get_member(output, obj, "initialblockdownload");
	if (!t || !json_to_bool(output, t, &ibd))
		fatal("Invalid 'initialblockdownload' field in getblockchaininfo '%.*s'",
		      (int)output_len, output);

	if (ibd) {
		if (initial)
			log_unusual(zcored->log,
				    "Waiting for initial block download"
				    " (this can take a while!)");
		else
			log_debug(zcored->log,
				  "Still waiting for initial block download");
	} else if (headers != blocks) {
		if (initial)
			log_unusual(zcored->log,
				    "Waiting for zcored to catch up"
				    " (%u blocks of %u)",
				    blocks, headers);
		else
			log_debug(zcored->log,
				  "Waiting for zcored to catch up"
				  " (%u blocks of %u)",
				  blocks, headers);
	} else {
		if (!initial)
			log_info(zcored->log, "ZCored now synced.");
		zcored->synced = true;
		return;
	}

	zcored->synced = false;
	notleak(new_reltimer(zcored->ld->timers, zcored,
			     /* Be 4x more aggressive in this case. */
			     time_divide(time_from_sec(zcored->ld->topology
						       ->poll_seconds), 4),
			     retry_getblockchaininfo, zcored));
}

static bool process_getblockchaininfo(struct zcore_cli *bcli)
{
	const jsmntok_t *tokens;
	bool valid;

	tokens = json_parse_input(bcli, bcli->output, bcli->output_bytes,
				  &valid);
	if (!tokens)
		fatal("%s: %s response (%.*s)",
		      bcli_args(tmpctx, bcli),
		      valid ? "partial" : "invalid",
		      (int)bcli->output_bytes, bcli->output);

	if (tokens[0].type != JSMN_OBJECT) {
		log_unusual(bcli->zcored->log,
			    "%s: gave non-object (%.*s)?",
			    bcli_args(tmpctx, bcli),
			    (int)bcli->output_bytes, bcli->output);
		return false;
	}

	is_zcored_synced_yet(bcli->zcored, bcli->output, bcli->output_bytes,
			       tokens, false);
	return true;
}

static void destroy_zcored(struct zcored *zcored)
{
	/* Suppresses the callbacks from bcli_finished as we free conns. */
	zcored->shutdown = true;
}

static const char **cmdarr(const tal_t *ctx, const struct zcored *zcored,
			   const char *cmd, ...)
{
	va_list ap;
	const char **args;

	va_start(ap, cmd);
	args = gather_args(zcored, ctx, cmd, ap);
	va_end(ap);
	return args;
}

static void fatal_zcored_failure(struct zcored *zcored, const char *error_message)
{
	const char **cmd = cmdarr(zcored, zcored, "echo", NULL);

	fprintf(stderr, "%s\n\n", error_message);
	fprintf(stderr, "Make sure you have zcored running and that zcore-cli is able to connect to zcored.\n\n");
	fprintf(stderr, "You can verify that your ZCore Core installation is ready for use by running:\n\n");
	fprintf(stderr, "    $ %s 'hello world'\n", args_string(cmd, cmd));
	tal_free(cmd);
	exit(1);
}

/* This function is used to check "chain" field from
 * zcore-cli "getblockchaininfo" API */
static char* check_blockchain_from_zcorecli(const tal_t *ctx,
				struct zcored *zcored,
				char* output, const char **cmd)
{
	size_t output_bytes;
	const jsmntok_t *tokens, *valuetok;
	bool valid;

	if (!output)
		return tal_fmt(ctx, "Reading from %s failed: %s",
			       args_string(tmpctx, cmd), strerror(errno));

	output_bytes = tal_count(output);

	tokens = json_parse_input(cmd, output, output_bytes,
			          &valid);

	if (!tokens)
		return tal_fmt(ctx, "%s: %s response",
			       args_string(tmpctx, cmd),
			       valid ? "partial" : "invalid");

	if (tokens[0].type != JSMN_OBJECT)
		return tal_fmt(ctx, "%s: gave non-object (%.*s)?",
			       args_string(tmpctx, cmd),
			       (int)output_bytes, output);

	valuetok = json_get_member(output, tokens, "chain");
	if (!valuetok)
		return tal_fmt(ctx, "%s: had no chain member (%.*s)?",
			       args_string(tmpctx, cmd),
			       (int)output_bytes, output);

	if(!json_tok_streq(output, valuetok,
			   zcored->chainparams->bip70_name))
		return tal_fmt(ctx, "Error blockchain for zcore-cli?"
			       " Should be: %s",
			       zcored->chainparams->bip70_name);

	is_zcored_synced_yet(zcored, output, output_bytes, tokens, true);
	return NULL;
}

void wait_for_zcored(struct zcored *zcored)
{
	int from, status, ret;
	pid_t child;
	const char **cmd = cmdarr(zcored, zcored, "getblockchaininfo", NULL);
	bool printed = false;
	char *errstr;

	for (;;) {
		child = pipecmdarr(NULL, &from, &from, cast_const2(char **,cmd));
		if (child < 0) {
			if (errno == ENOENT) {
				fatal_zcored_failure(zcored, "zcore-cli not found. Is zcore-cli (part of ZCore Core) available in your PATH?");
			}
			fatal("%s exec failed: %s", cmd[0], strerror(errno));
		}

		char *output = grab_fd(cmd, from);

		while ((ret = waitpid(child, &status, 0)) < 0 && errno == EINTR);
		if (ret != child)
			fatal("Waiting for %s: %s", cmd[0], strerror(errno));
		if (!WIFEXITED(status))
			fatal("Death of %s: signal %i",
			      cmd[0], WTERMSIG(status));

		if (WEXITSTATUS(status) == 0) {
			/* If succeeded, so check answer it gave. */
			errstr = check_blockchain_from_zcorecli(tmpctx, zcored, output, cmd);
			if (errstr)
				fatal("%s", errstr);

			break;
		}

		/* zcore/src/rpc/protocol.h:
		 *	RPC_IN_WARMUP = -28, //!< Client still warming up
		 */
		if (WEXITSTATUS(status) != 28) {
			if (WEXITSTATUS(status) == 1) {
				fatal_zcored_failure(zcored, "Could not connect to zcored using zcore-cli. Is zcored running?");
			}
			fatal("%s exited with code %i: %s",
			      cmd[0], WEXITSTATUS(status), output);
		}

		if (!printed) {
			log_unusual(zcored->log,
				    "Waiting for zcored to warm up...");
			printed = true;
		}
		sleep(1);
	}
	tal_free(cmd);
}

struct zcored *new_zcored(const tal_t *ctx,
			      struct lightningd *ld,
			      struct log *log)
{
	struct zcored *zcored = tal(ctx, struct zcored);

	/* Use testnet by default, change later if we want another network */
	zcored->chainparams = chainparams_for_network("testnet");
	zcored->cli = NULL;
	zcored->datadir = NULL;
	zcored->ld = ld;
	zcored->log = log;
	for (size_t i = 0; i < ZCORED_NUM_PRIO; i++) {
		zcored->num_requests[i] = 0;
		list_head_init(&zcored->pending[i]);
	}
	list_head_init(&zcored->pending_getfilteredblock);
	zcored->shutdown = false;
	zcored->error_count = 0;
	zcored->retry_timeout = 60;
	zcored->rpcuser = NULL;
	zcored->rpcpass = NULL;
	zcored->rpcconnect = NULL;
	zcored->rpcport = NULL;
	tal_add_destructor(zcored, destroy_zcored);

	return zcored;
}
