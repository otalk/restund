/**
 * @file stun.c  STUN Server
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <re.h>
#include <restund.h>
#include "stund.h"


const char *restund_software = "restund v" VERSION " (" ARCH "/" OS ")";


static struct {
	struct list stunl;
} stn;


void restund_process_msg(int proto, void *sock,
			 const struct sa *src, const struct sa *dst,
			 struct mbuf *mb)
{
	struct le *le = stn.stunl.head;
	struct restund_msgctx ctx;
	struct stun_msg *msg;
	int err;

	if (!sock || !src || !dst || !mb)
		return;

	err = stun_msg_decode(&msg, mb, &ctx.ua);
	if (err) {
		while (le) {
			struct restund_stun *st = le->data;

			le = le->next;

			if (st->rawh && st->rawh(proto, src, dst, mb))
				break;
		}

		return;
	}

	ctx.key = NULL;
	ctx.keylen = 0;
	ctx.fp = false;

#if 0
	stun_msg_dump(msg);
#endif

	switch (stun_msg_class(msg)) {

	case STUN_CLASS_REQUEST:
		while (le) {
			struct restund_stun *st = le->data;

			le = le->next;

			if (st->reqh &&
			    st->reqh(&ctx, proto, sock, src, dst, msg))
				break;
		}
		break;

	case STUN_CLASS_INDICATION:
		while (le) {
			struct restund_stun *st = le->data;

			le = le->next;

			if (st->indh &&
			    st->indh(&ctx, proto, sock, src, dst, msg))
				break;
		}
		break;

	default:
		restund_debug("stun: unhandled msg class (%u) from %J\n",
			      stun_msg_class(msg), src);
		break;
	}

	mem_deref(ctx.key);
	mem_deref(msg);
}


void restund_stun_register_handler(struct restund_stun *stun)
{
	if (!stun)
		return;

	list_append(&stn.stunl, &stun->le, stun);
}


void restund_stun_unregister_handler(struct restund_stun *stun)
{
	if (!stun)
		return;

	list_unlink(&stun->le);
}
