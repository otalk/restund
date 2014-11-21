/**
 * @file turn.c Turn Server
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <string.h>
#include <re.h>
#include <restund.h>
#include "turn.h"


enum {
	ALLOC_DEFAULT_BSIZE = 512,
};


struct tuple {
	const struct sa *cli_addr;
	const struct sa *srv_addr;
	int proto;
};


static struct turnd turnd;


struct turnd *turndp(void)
{
	return &turnd;
}


static bool hash_cmp_handler(struct le *le, void *arg)
{
	const struct allocation *al = le->data;
	const struct tuple *tup = arg;

	if (!sa_cmp(&al->cli_addr, tup->cli_addr, SA_ALL))
		return false;

	if (!sa_cmp(&al->srv_addr, tup->srv_addr, SA_ALL))
		return false;

	if (al->proto != tup->proto)
		return false;

	return true;
}


static struct allocation *allocation_find(int proto, const struct sa *src,
					  const struct sa *dst)
{
	struct tuple tup;

	tup.cli_addr = src;
	tup.srv_addr = dst;
	tup.proto = proto;

	return list_ledata(hash_lookup(turnd.ht_alloc, sa_hash(src, SA_ALL),
				       hash_cmp_handler, &tup));
}


static bool request_handler(struct restund_msgctx *ctx, int proto, void *sock,
			    const struct sa *src, const struct sa *dst,
			    const struct stun_msg *msg)
{
	const uint16_t met = stun_msg_method(msg);
	struct allocation *al;
	int err = 0;

	switch (met) {

	case STUN_METHOD_ALLOCATE:
	case STUN_METHOD_REFRESH:
	case STUN_METHOD_CREATEPERM:
	case STUN_METHOD_CHANBIND:
		break;

	default:
		return false;
	}

	if (ctx->ua.typec > 0) {
		err = stun_ereply(proto, sock, src, 0, msg,
				  420, "Unknown Attribute",
				  ctx->key, ctx->keylen, ctx->fp, 2,
				  STUN_ATTR_UNKNOWN_ATTR, &ctx->ua,
				  STUN_ATTR_SOFTWARE, restund_software);
		goto out;
	}

	al = allocation_find(proto, src, dst);

	if (!al && met != STUN_METHOD_ALLOCATE) {
		restund_debug("turn: allocation does not exist\n");
		err = stun_ereply(proto, sock, src, 0, msg,
				  437, "Allocation Mismatch",
				  ctx->key, ctx->keylen, ctx->fp, 1,
				  STUN_ATTR_SOFTWARE, restund_software);
		goto out;
	}

	if (al && al->username && ctx->key) {

		struct stun_attr *usr = stun_msg_attr(msg, STUN_ATTR_USERNAME);

		if (!usr || strcmp(usr->v.username, al->username)) {
			restund_debug("turn: wrong credetials\n");
			err = stun_ereply(proto, sock, src, 0, msg,
					  441, "Wrong Credentials",
					  ctx->key, ctx->keylen, ctx->fp, 1,
					  STUN_ATTR_SOFTWARE,restund_software);
			goto out;
		}
	}

	switch (met) {

	case STUN_METHOD_ALLOCATE:
		allocate_request(&turnd, al, ctx, proto, sock, src, dst, msg);
		break;

	case STUN_METHOD_REFRESH:
		refresh_request(&turnd, al, ctx, proto, sock, src, msg);
		break;

	case STUN_METHOD_CREATEPERM:
		createperm_request(al, ctx, proto, sock, src, msg);
		break;

	case STUN_METHOD_CHANBIND:
		chanbind_request(al, ctx, proto, sock, src, msg);
		break;
	}

 out:
	if (err) {
		restund_warning("turn reply error: %m\n", err);
	}

	return true;
}


static bool indication_handler(struct restund_msgctx *ctx, int proto,
			       void *sock, const struct sa *src,
			       const struct sa *dst,
			       const struct stun_msg *msg)
{
	struct stun_attr *data, *peer;
	struct allocation *al;
	struct perm *perm;
	int err;
	(void)sock;
	(void)ctx;

	if (stun_msg_method(msg) != STUN_METHOD_SEND)
		return false;

	if (ctx->ua.typec > 0)
		return true;

	al = allocation_find(proto, src, dst);
	if (!al)
		return true;

	peer = stun_msg_attr(msg, STUN_ATTR_XOR_PEER_ADDR);
	data = stun_msg_attr(msg, STUN_ATTR_DATA);

	if (!peer || !data)
		return true;

	perm = perm_find(al->perms, &peer->v.xor_peer_addr);
	if (!perm) {
		++al->dropc_tx;
		return true;
	}

	err = udp_send(al->rel_us, &peer->v.xor_peer_addr, &data->v.data);
	if (err)
		turnd.errc_tx++;
	else {
		const size_t bytes = mbuf_get_left(&data->v.data);

		perm_tx_stat(perm, bytes);
		turnd.bytec_tx += bytes;
	}

	return true;
}


static bool raw_handler(int proto, const struct sa *src,
			const struct sa *dst, struct mbuf *mb)
{
	struct allocation *al;
	uint16_t numb, len;
	struct perm *perm;
	struct chan *chan;
	int err;

	al = allocation_find(proto, src, dst);
	if (!al)
		return false;

	if (mbuf_get_left(mb) < 4)
		return false;

	numb = ntohs(mbuf_read_u16(mb));
	len  = ntohs(mbuf_read_u16(mb));

	if (mbuf_get_left(mb) < len)
		return false;

	chan = chan_numb_find(al->chans, numb);
	if (!chan)
		return false;

	perm = perm_find(al->perms, chan_peer(chan));
	if (!perm) {
		++al->dropc_tx;
		return false;
	}

	err = udp_send(al->rel_us, chan_peer(chan), mb);
	if (err)
		turnd.errc_tx++;
	else {
		const size_t bytes = mbuf_get_left(mb);

		perm_tx_stat(perm, bytes);
		turnd.bytec_tx += bytes;
	}

	return true;
}


static bool allocation_status(struct le *le, void *arg)
{
	const uint32_t bsize = hash_bsize(turnd.ht_alloc);
	struct allocation *al = le->data;
	struct mbuf *mb = arg;

	(void)mbuf_printf(mb,
			  "- %04u %s/%J/%J - %J \"%s\" %us (drop %llu/%llu)\n",
			  sa_hash(&al->cli_addr, SA_ALL) & (bsize - 1),
			  net_proto2name(al->proto), &al->cli_addr,
			  &al->srv_addr, &al->rel_addr, al->username,
			  (uint32_t)tmr_get_expire(&al->tmr) / 1000,
			  al->dropc_tx, al->dropc_rx);

	perm_status(al->perms, mb);
	chan_status(al->chans, mb);

	return false;
}


static void status_handler(struct mbuf *mb)
{
	(void)mbuf_printf(mb, "TURN relay=%j relay6=%j (err %llu/%llu)\n",
			  &turnd.rel_addr, &turnd.rel_addr6,
			  turnd.errc_tx, turnd.errc_rx);
	(void)hash_apply(turnd.ht_alloc, allocation_status, mb);
}


static void stats_handler(struct mbuf *mb)
{
	(void)mbuf_printf(mb, "allocs_cur %u\n", turnd.allocc_cur);
	(void)mbuf_printf(mb, "allocs_tot %llu\n", turnd.allocc_tot);
	(void)mbuf_printf(mb, "bytes_tx %llu\n", turnd.bytec_tx);
	(void)mbuf_printf(mb, "bytes_rx %llu\n", turnd.bytec_rx);
	(void)mbuf_printf(mb, "bytes_tot %llu\n",
			  turnd.bytec_tx + turnd.bytec_rx);
	(void)mbuf_printf(mb, "chan_cur %llu\n", turnd.chan_cur);
}


static struct restund_stun stun = {
	.reqh = request_handler,
	.indh = indication_handler,
	.rawh = raw_handler,
};


static struct restund_cmdsub cmd_turn = {
	.cmdh = status_handler,
	.cmd  = "turn",
};


static struct restund_cmdsub cmd_turnstats = {
	.cmdh = stats_handler,
	.cmd  = "turnstats",
};


static int module_init(void)
{
	uint32_t x, bsize = ALLOC_DEFAULT_BSIZE;
	struct pl opt;
	int err = 0;

	restund_stun_register_handler(&stun);
	restund_cmd_subscribe(&cmd_turn);
	restund_cmd_subscribe(&cmd_turnstats);

	/* turn_external_addr */
	if (!conf_get(restund_conf(), "turn_relay_addr", &opt))
		err = sa_set(&turnd.rel_addr, &opt, 0);
	else
		sa_init(&turnd.rel_addr, AF_UNSPEC);

	if (err) {
		restund_error("turn: bad turn_relay_addr: '%r'\n", &opt);
		goto out;
	}

	/* turn_external_addr6 */
	if (!conf_get(restund_conf(), "turn_relay_addr6", &opt))
		err = sa_set(&turnd.rel_addr6, &opt, 0);
	else
		sa_init(&turnd.rel_addr6, AF_UNSPEC);

	if (err) {
		restund_error("turn: bad turn_relay_addr6: '%r'\n", &opt);
		goto out;
	}

	if (!sa_isset(&turnd.rel_addr, SA_ADDR) &&
	    !sa_isset(&turnd.rel_addr6, SA_ADDR)) {
		restund_error("turn: no relay address configured\n");
		err = EINVAL;
		goto out;
	}

	/* turn_max_lifetime, turn_max_allocations, udp_sockbuf_size */
	turnd.lifetime_max = TURN_DEFAULT_LIFETIME;
	conf_get_u32(restund_conf(), "turn_max_lifetime", &turnd.lifetime_max);
	conf_get_u32(restund_conf(), "turn_max_allocations", &bsize);
	conf_get_u32(restund_conf(), "udp_sockbuf_size",
		     &turnd.udp_sockbuf_size);

	for (x=2; (uint32_t)1<<x<bsize; x++);
	bsize = 1<<x;

	err = hash_alloc(&turnd.ht_alloc, bsize);
	if (err) {
		restund_error("turnd hash alloc error: %m\n", err);
		goto out;
	}

	restund_debug("turn: lifetime=%u ext=%j ext6=%j bsz=%u\n",
		      turnd.lifetime_max, &turnd.rel_addr, &turnd.rel_addr6,
		      bsize);

 out:
	return err;
}


static int module_close(void)
{
	hash_flush(turnd.ht_alloc);
	turnd.ht_alloc = mem_deref(turnd.ht_alloc);
	restund_cmd_unsubscribe(&cmd_turnstats);
	restund_cmd_unsubscribe(&cmd_turn);
	restund_stun_unregister_handler(&stun);

	restund_debug("turn: module closed\n");

	return 0;
}


const struct mod_export exports = {
	.name = "turn",
	.type = "stun relay",
	.init = module_init,
	.close = module_close,
};
