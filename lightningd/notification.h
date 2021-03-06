#ifndef LIGHTNING_LIGHTNINGD_NOTIFICATION_H
#define LIGHTNING_LIGHTNINGD_NOTIFICATION_H
#include "config.h"
#include <zcore/short_channel_id.h>
#include <zcore/tx.h>
#include <ccan/autodata/autodata.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/time/time.h>
#include <common/amount.h>
#include <common/node_id.h>
#include <lightningd/htlc_end.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/pay.h>
#include <lightningd/plugin.h>
#include <wallet/wallet.h>
#include <wire/gen_onion_wire.h>

bool notifications_have_topic(const char *topic);

struct notification {
	const char *topic;
	/* the serialization interface */
	void *serialize;
};

AUTODATA_TYPE(notifications, struct notification);

/* FIXME: Find a way to avoid back-to-back declaration and definition */
#define REGISTER_NOTIFICATION(topic, serialize)                                  \
	struct notification topic##_notification_gen = {                         \
		stringify(topic),                                                \
		serialize,                                                       \
	};                                                                       \
	AUTODATA(notifications, &topic##_notification_gen);

void notify_connect(struct lightningd *ld, struct node_id *nodeid,
		    struct wireaddr_internal *addr);
void notify_disconnect(struct lightningd *ld, struct node_id *nodeid);

void notify_warning(struct lightningd *ld, struct log_entry *l);

void notify_invoice_payment(struct lightningd *ld, struct amount_msat amount,
			    struct preimage preimage, const struct json_escape *label);

void notify_channel_opened(struct lightningd *ld, struct node_id *node_id,
			   struct amount_sat *funding_sat, struct zcore_txid *funding_txid,
			   bool *funding_locked);

void notify_forward_event(struct lightningd *ld,
			  const struct htlc_in *in,
			  const struct htlc_out *out,
			  enum forward_status state,
			  enum onion_type failcode,
			  struct timeabs *resolved_time);

void notify_sendpay_success(struct lightningd *ld,
			    const struct wallet_payment *payment);

void notify_sendpay_failure(struct lightningd *ld,
			    const struct wallet_payment *payment,
			    int pay_errcode,
			    const u8 *onionreply,
			    const struct routing_failure *fail,
			    char *errmsg);

#endif /* LIGHTNING_LIGHTNINGD_NOTIFICATION_H */
