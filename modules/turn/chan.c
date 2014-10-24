/**
 * @file turn.c Turn Server Channel
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <time.h>
#include <re.h>
#include <restund.h>
#include "turn.h"


enum {
	CHAN_NUMB_MIN = 0x4000,
	CHAN_NUMB_MAX = 0x7fff,
	CHAN_LIFETIME = 600,
};


struct chanlist {
	struct hash *ht_numb;
	struct hash *ht_peer;
};


struct chan {
	struct le he_numb;
	struct le he_peer;
	struct sa peer;
	const struct allocation *al;
	time_t expires;
	uint16_t numb;
};


static void chanlist_destructor(void *arg)
{
	struct chanlist *cl = arg;

	hash_flush(cl->ht_numb);
	mem_deref(cl->ht_numb);
	mem_deref(cl->ht_peer);
}


static void destructor(void *arg)
{
	struct chan *chan = arg;

	restund_debug("turn: allocation %p channel 0x%x %J destroyed\n",
		      chan->al, chan->numb, &chan->peer);

	hash_unlink(&chan->he_numb);
	hash_unlink(&chan->he_peer);
    turndp()->chan_cur--;
}


static bool hash_numb_cmp_handler(struct le *le, void *arg)
{
	const struct chan *chan = le->data;
	const uint16_t *numb = arg;

	return chan->numb == *numb;
}


static bool hash_peer_cmp_handler(struct le *le, void *arg)
{
	const struct chan *chan = le->data;

	return sa_cmp(&chan->peer, arg, SA_ALL);
}


struct chan *chan_numb_find(const struct chanlist *cl, uint16_t numb)
{
	struct chan *chan;

	if (!cl)
		return NULL;

	chan = list_ledata(hash_lookup(cl->ht_numb, numb,
				       hash_numb_cmp_handler, &numb));
	if (!chan)
		return NULL;

	if (chan->expires < time(NULL)) {
		restund_debug("turn: allocation %p channel 0x%x %J expired\n",
			      chan->al, chan->numb, &chan->peer);
		mem_deref(chan);
		return NULL;
	}

	return chan;
}


struct chan *chan_peer_find(const struct chanlist *cl, const struct sa *peer)
{
	struct chan *chan;

	if (!cl || !peer)
		return NULL;

	chan = list_ledata(hash_lookup(cl->ht_peer, sa_hash(peer, SA_ALL),
				       hash_peer_cmp_handler, (void *)peer));
	if (!chan)
		return NULL;

	if (chan->expires < time(NULL)) {
		restund_debug("turn: allocation %p channel 0x%x %J expired\n",
			      chan->al, chan->numb, &chan->peer);
		mem_deref(chan);
		return NULL;
	}

	return chan;
}


uint16_t chan_numb(const struct chan *chan)
{
	return chan ? chan->numb : 0;
}


const struct sa *chan_peer(const struct chan *chan)
{
	return chan ? &chan->peer : NULL;
}


int chanlist_alloc(struct chanlist **clp, uint32_t bsize)
{
	struct chanlist *cl;
	int err;

	if (!clp)
		return EINVAL;

	cl = mem_zalloc(sizeof(*cl), chanlist_destructor);
	if (!cl)
		return ENOMEM;

	err = hash_alloc(&cl->ht_numb, bsize);
	if (err)
		goto out;

	err = hash_alloc(&cl->ht_peer, bsize);
	if (err)
		goto out;

 out:
	if (err)
		cl = mem_deref(cl);
	else
		*clp = cl;

	return err;
}


static bool status_handler(struct le *le, void *arg)
{
	struct chan *chan = le->data;
	struct mbuf *mb = arg;

	(void)mbuf_printf(mb, " (0x%x %J %is)", chan->numb, &chan->peer,
			  chan->expires - time(NULL));

	return false;
}


void chan_status(const struct chanlist *cl, struct mbuf *mb)
{
	if (!cl || !mb)
		return;

	(void)mbuf_printf(mb, "    channels:   ");
	(void)hash_apply(cl->ht_numb, status_handler, mb);
	(void)mbuf_printf(mb, "\n");
}


static struct chan *chan_create(struct chanlist *cl, uint16_t numb,
				const struct sa *peer,
				const struct allocation *al)
{
	struct chan *chan;

	if (!cl || !peer)
		return NULL;

	chan = mem_zalloc(sizeof(*chan), destructor);
	if (!chan)
		return NULL;

	hash_append(cl->ht_numb, numb, &chan->he_numb, chan);
	hash_append(cl->ht_peer, sa_hash(peer, SA_ALL), &chan->he_peer, chan);

	chan->peer = *peer;
	chan->numb = numb;
	chan->al = al;
	chan->expires = time(NULL) + CHAN_LIFETIME;

	restund_debug("turn: allocation %p channel 0x%x %J created\n",
		      chan->al, chan->numb, &chan->peer);
    turndp()->chan_cur++;

	return chan;
}


static void chan_refresh(struct chan *chan)
{
	if (!chan)
		return;

	chan->expires = time(NULL) + CHAN_LIFETIME;

	restund_debug("turn: allocation %p channel 0x%x %J refreshed\n",
		      chan->al, chan->numb, &chan->peer);
}


static bool chan_numb_valid(uint16_t numb)
{
	return CHAN_NUMB_MIN <= numb && numb <= CHAN_NUMB_MAX;
}


void chanbind_request(struct allocation *al, struct restund_msgctx *ctx,
		      int proto, void *sock, const struct sa *src,
		      const struct stun_msg *msg)
{
	struct chan *chan = NULL, *ch_numb = NULL, *ch_peer;
	struct perm *perm = NULL, *permx = NULL;
	struct stun_attr *chnr, *peer;
	int err = ENOMEM, rerr;

	chnr = stun_msg_attr(msg, STUN_ATTR_CHANNEL_NUMBER);
	peer = stun_msg_attr(msg, STUN_ATTR_XOR_PEER_ADDR);

	if (!chnr || !chan_numb_valid(chnr->v.channel_number) || !peer) {
		restund_info("turn: bad chanbind attributes\n");
		rerr = stun_ereply(proto, sock, src, 0, msg,
				   400, "Bad Attributes",
				   ctx->key, ctx->keylen, ctx->fp, 1,
				   STUN_ATTR_SOFTWARE, restund_software);
		goto out;
	}

	if (sa_af(&peer->v.xor_peer_addr) != sa_af(&al->rel_addr)) {
		restund_info("turn: chanbind peer address family mismatch\n");
		rerr = stun_ereply(proto, sock, src, 0, msg,
				   443, "Peer Address Family Mismatch",
				   ctx->key, ctx->keylen, ctx->fp, 1,
				   STUN_ATTR_SOFTWARE, restund_software);
		goto out;
	}

	ch_numb = chan_numb_find(al->chans, chnr->v.channel_number);
	ch_peer = chan_peer_find(al->chans, &peer->v.xor_peer_addr);

	if (ch_numb != ch_peer) {
		restund_info("turn: channel %p/peer %p already bound\n",
			     ch_numb, ch_peer);
		rerr = stun_ereply(proto, sock, src, 0, msg,
				   400, "Channel/Peer Already Bound",
				   ctx->key, ctx->keylen, ctx->fp, 1,
				   STUN_ATTR_SOFTWARE, restund_software);
		goto out;
	}

	if (!ch_numb) {
		chan = chan_create(al->chans, chnr->v.channel_number,
				   &peer->v.xor_peer_addr, al);
		if (!chan) {
			restund_info("turn: unable to create channel\n");
			rerr = stun_ereply(proto, sock, src, 0, msg,
					  500, "Server Error",
					  ctx->key, ctx->keylen, ctx->fp, 1,
					  STUN_ATTR_SOFTWARE,restund_software);
			goto out;
		}
	}

	permx = perm_find(al->perms, &peer->v.xor_peer_addr);
	if (!permx) {
		perm = perm_create(al->perms, &peer->v.xor_peer_addr, al);
		if (!perm) {
			restund_info("turn: unable to create permission\n");
			rerr = stun_ereply(proto, sock, src, 0, msg,
					  500, "Server Error",
					  ctx->key, ctx->keylen, ctx->fp, 1,
					  STUN_ATTR_SOFTWARE,restund_software);
			goto out;
		}
	}

	err = rerr = stun_reply(proto, sock, src, 0, msg,
				ctx->key, ctx->keylen, ctx->fp, 1,
				STUN_ATTR_SOFTWARE, restund_software);
 out:
	if (rerr)
		restund_warning("turn: chanbind reply: %m\n", rerr);

	if (err) {
		mem_deref(chan);
		mem_deref(perm);
	}
	else {
		chan_refresh(ch_numb);
		perm_refresh(permx);
	}
}
