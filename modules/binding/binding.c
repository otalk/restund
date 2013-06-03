/**
 * @file stun.c  STUN Binding Server
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <re.h>
#include <restund.h>


/*
 * To enable NATBD mode we must listen to 3 UDP sockets:
 *
 *     1.2.3.4:3478
 *     5.6.7.8:3478
 *     5.6.7.8:3479
 */


static void *get_sock(struct sa *sa, int proto, const struct sa *orig,
		      bool ch_ip, bool ch_port)
{
	switch (proto) {

	case IPPROTO_UDP:
		return restund_udp_socket(sa, orig, ch_ip, ch_port);

	case IPPROTO_TCP:
		return restund_tcp_socket(sa, orig, ch_ip, ch_port);

	default:
		return 0;
	}
}


static bool request_handler(struct restund_msgctx *ctx, int proto, void *sock,
			    const struct sa *src, const struct sa *dst,
			    const struct stun_msg *msg)
{
	const struct stun_attr *rp, *cr;
	struct sa other, peer = *src;
	int err;

	if (stun_msg_method(msg) != STUN_METHOD_BINDING)
		return false;

	restund_debug("binding: request from %J\n", src);

	if (ctx->ua.typec > 0) {
		err = stun_ereply(proto, sock, src, 0, msg,
				  420, "Unknown Attribute",
				  ctx->key, ctx->keylen, ctx->fp, 2,
				  STUN_ATTR_UNKNOWN_ATTR, &ctx->ua,
				  STUN_ATTR_SOFTWARE, restund_software);
		goto out;
	}

	/* OTHER-ADDRESS is always in Binding Response
	   if server supports second IP address */
	if (!get_sock(&other, proto, dst, true, true))
		sa_init(&other, AF_UNSPEC);

	rp = stun_msg_attr(msg, STUN_ATTR_RESP_PORT);
	if (rp) {
		/* Update Response Address */
		sa_set_port(&peer, rp->v.resp_port);
	}

	/* CHANGE-REQUEST applies only to UDP Datagrams */
	cr = stun_msg_attr(msg, STUN_ATTR_CHANGE_REQ);
	if (cr && (IPPROTO_UDP == proto)) {
		void *s = get_sock(NULL, proto, dst, cr->v.change_req.ip,
				   cr->v.change_req.port);
		sock = s ? s : sock;
	}

	/* The server MUST add a RESPONSE-ORIGIN attribute to the Binding
	   Response, containing the source address and port used to send the
	   Binding Response.
	 */

	err = stun_reply(proto, sock, &peer, 0, msg,
			 ctx->key, ctx->keylen, ctx->fp, 5,
			 STUN_ATTR_XOR_MAPPED_ADDR, src,
			 STUN_ATTR_MAPPED_ADDR, src,
			 STUN_ATTR_OTHER_ADDR,
			     sa_isset(&other, SA_ALL) ? &other : NULL,
			 STUN_ATTR_RESP_ORIGIN, dst,
			 STUN_ATTR_SOFTWARE, restund_software);

 out:
	if (err) {
		restund_warning("binding reply error: %m\n", err);
	}

	return true;
}


static struct restund_stun stun = {
	.reqh = request_handler,
};


static int module_init(void)
{
	restund_stun_register_handler(&stun);

	restund_debug("binding: module loaded\n");

	return 0;
}


static int module_close(void)
{
	restund_stun_unregister_handler(&stun);

	restund_debug("binding: module closed\n");

	return 0;
}


const struct mod_export exports = {
	.name = "binding",
	.type = "stun",
	.init = module_init,
	.close = module_close,
};
