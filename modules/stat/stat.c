/**
 * @file stat.c  Statistics module
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <string.h>
#include <re.h>
#include <restund.h>


/*
 * The statistics module is collecting information about how many STUN
 * messages have been handled on so on. In order to be effective, this
 * module must be loaded before the other STUN message handler modules
 * such as stun.so, turn.so and natbd.so
 */


#define STAT_INC(var)         ++(stat.var)           /**< Stats inc */


static struct {
	uint32_t n_bind_req;
	uint32_t n_alloc_req;
	uint32_t n_refresh_req;
	uint32_t n_chanbind_req;
	uint32_t n_unk_req;
} stat;


static bool request_handler(struct restund_msgctx *ctx, int proto, void *sock,
			    const struct sa *src, const struct sa *dst,
			    const struct stun_msg *msg)
{
	(void)ctx;
	(void)proto;
	(void)sock;
	(void)src;
	(void)dst;

	switch (stun_msg_method(msg)) {

	case STUN_METHOD_BINDING:
		STAT_INC(n_bind_req);
		break;

	case STUN_METHOD_ALLOCATE:
		STAT_INC(n_alloc_req);
		break;

	case STUN_METHOD_REFRESH:
		STAT_INC(n_refresh_req);
		break;

	case STUN_METHOD_CHANBIND:
		STAT_INC(n_chanbind_req);
		break;

	default:
		/* Must also work for multiplexed payloads */
		if (!stun_msg_mcookie(msg))
			break;

		STAT_INC(n_unk_req);
		break;
	}

	return false;
}


static void print_stat(struct mbuf *mb)
{
	(void)mbuf_printf(mb, "binding_req %u\n", stat.n_bind_req);
	(void)mbuf_printf(mb, "allocate_req %u\n", stat.n_alloc_req);
	(void)mbuf_printf(mb, "refresh_req %u\n", stat.n_refresh_req);
	(void)mbuf_printf(mb, "chanbind_req %u\n", stat.n_chanbind_req);
	(void)mbuf_printf(mb, "unknown_req %u\n", stat.n_unk_req);
}


static struct restund_stun stun = {
	.reqh = request_handler
};


static struct restund_cmdsub cmd_stat = {
	.cmdh = print_stat,
	.cmd  = "stat",
};


static int module_init(void)
{
	restund_stun_register_handler(&stun);
	restund_cmd_subscribe(&cmd_stat);

	restund_debug("stat: module loaded\n");

	return 0;
}


static int module_close(void)
{
	restund_cmd_unsubscribe(&cmd_stat);
	restund_stun_unregister_handler(&stun);

	restund_debug("stat: module closed\n");

	return 0;
}


const struct mod_export exports = {
	.name  = "stat",
	.type  = "stun",
	.init  = module_init,
	.close = module_close
};
