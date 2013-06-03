/**
 * @file udp.c UDP Transport
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <re.h>
#include <restund.h>
#include "stund.h"


struct udp_lstnr {
	struct le le;
	struct sa bnd_addr;
	struct udp_sock *us;
};


static struct list lstnrl;


static void udp_recv(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct udp_lstnr *ul = arg;

	restund_process_msg(IPPROTO_UDP, ul->us, src, &ul->bnd_addr, mb);
}


static void destructor(void *arg)
{
	struct udp_lstnr *ul = arg;

	list_unlink(&ul->le);
	mem_deref(ul->us);
}


static int listen_handler(const struct pl *addrport, void *arg)
{
	uint32_t sockbuf_size = *(uint32_t *)arg;
	struct udp_lstnr *ul = NULL;
	int err = ENOMEM;

	ul = mem_zalloc(sizeof(*ul), destructor);
	if (!ul) {
		restund_warning("udp listen error: %m\n", err);
		goto out;
	}

	list_append(&lstnrl, &ul->le, ul);

	err = sa_decode(&ul->bnd_addr, addrport->p, addrport->l);
	if (err || sa_is_any(&ul->bnd_addr) || !sa_port(&ul->bnd_addr)) {
		restund_warning("bad udp_listen directive: '%r'\n", addrport);
		err = EINVAL;
		goto out;
	}

	err = udp_listen(&ul->us, &ul->bnd_addr, udp_recv, ul);
	if (err) {
		restund_warning("udp listen %J: %m\n", &ul->bnd_addr, err);
		goto out;
	}

	if (sockbuf_size > 0)
		(void)udp_sockbuf_set(ul->us, sockbuf_size);

	restund_debug("udp listen: %J\n", &ul->bnd_addr);

 out:
	if (err)
		mem_deref(ul);

	return err;
}


int restund_udp_init(void)
{
	uint32_t sockbuf_size = 0;
	int err;

	list_init(&lstnrl);

	(void)conf_get_u32(restund_conf(), "udp_sockbuf_size", &sockbuf_size);

	err = conf_apply(restund_conf(), "udp_listen", listen_handler,
			 &sockbuf_size);
	if (err)
		goto out;

 out:
	if (err)
		restund_udp_close();

	return err;
}


void restund_udp_close(void)
{
	list_flush(&lstnrl);
}


struct udp_sock *restund_udp_socket(struct sa *sa, const struct sa *orig,
				    bool ch_ip, bool ch_port)
{
	struct le *le = list_head(&lstnrl);

	while (le) {
		struct udp_lstnr *ul = le->data;
		le = le->next;

		if (ch_ip && sa_cmp(orig, &ul->bnd_addr, SA_PORT))
			continue;

		if (ch_port && (sa_port(orig) == sa_port(&ul->bnd_addr)))
			continue;

		sa_cpy(sa, &ul->bnd_addr);
		return ul->us;
	}

	return NULL;
}
