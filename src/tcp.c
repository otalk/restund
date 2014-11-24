/**
 * @file tcp.c TCP Transport
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <time.h>
#include <re.h>
#include <restund.h>
#include "stund.h"


enum {
	TCP_MAX_LENGTH = 2048,
	TCP_MAX_TXQSZ  = 16384,
};


struct tcp_lstnr {
	struct le le;
	struct sa bnd_addr;
	struct tcp_sock *ts;
	struct tls *tls;
};

struct conn {
	struct le le;
	struct sa laddr;
	struct sa paddr;
	struct tcp_conn *tc;
	struct tls_conn *tlsc;
	struct mbuf *mb;
	time_t created;
};


static struct list lstnrl;
static struct list tcl;


static void conn_destructor(void *arg)
{
	struct conn *conn = arg;

	list_unlink(&conn->le);
	tcp_set_handlers(conn->tc, NULL, NULL, NULL, NULL);
	mem_deref(conn->tlsc);
	mem_deref(conn->tc);
	mem_deref(conn->mb);
}


static inline uint32_t refc_idle(struct conn *conn)
{
	return conn->tlsc ? 2 : 1;
}


static void tcp_recv(struct mbuf *mb, void *arg)
{
	struct conn *conn = arg;
	int err = 0;

	if (conn->mb) {
		size_t pos;

		pos = conn->mb->pos;

		conn->mb->pos = conn->mb->end;

		err = mbuf_write_mem(conn->mb, mbuf_buf(mb),mbuf_get_left(mb));
		if (err) {
			restund_warning("tcp: buffer write error: %m\n", err);
			goto out;
		}

		conn->mb->pos = pos;
	}
	else {
		conn->mb = mem_ref(mb);
	}

	for (;;) {

		size_t len, pos, end;
		uint16_t typ;

		if (mbuf_get_left(conn->mb) < 4)
			break;

		typ = ntohs(mbuf_read_u16(conn->mb));
		len = ntohs(mbuf_read_u16(conn->mb));

		if (len > TCP_MAX_LENGTH) {
			restund_debug("tcp: bad length: %zu\n", len);
			err = EBADMSG;
			goto out;
		}

		if (typ < 0x4000)
			len += STUN_HEADER_SIZE;
		else if (typ < 0x8000)
			len += 4;
		else {
			restund_debug("tcp: bad type: 0x%04x\n", typ);
			err = EBADMSG;
			goto out;
		}

		conn->mb->pos -= 4;

		if (mbuf_get_left(conn->mb) < len)
			break;

		pos = conn->mb->pos;
		end = conn->mb->end;

		conn->mb->end = pos + len;

		restund_process_msg(IPPROTO_TCP, conn->tc, &conn->paddr,
				    &conn->laddr, conn->mb);

		/* 4 byte alignment */
		while (len & 0x03)
			++len;

		conn->mb->pos = pos + len;
		conn->mb->end = end;

		if (conn->mb->pos >= conn->mb->end) {
			conn->mb = mem_deref(conn->mb);
			break;
		}
	}

 out:
	if (err) {
		if (mem_nrefs(conn->tc) <= refc_idle(conn))
			mem_deref(conn);
		else
			conn->mb = mem_deref(conn->mb);
	}
}


static void tcp_close(int err, void *arg)
{
	struct conn *conn = arg;

	restund_debug("tcp: connection closed: %m\n", err);

	mem_deref(conn);
}


static void tcp_conn_handler(const struct sa *peer, void *arg)
{
	const time_t now = time(NULL);
	struct tcp_lstnr *tl = arg;
	struct conn *conn, *xconn;
	int err;
	struct le *le;

	restund_debug("tcp: connect from: %J\n", peer);
	
	/* close any unused connections */
	for (le=tcl.head; le; le=le->next) {
		xconn = le->data;
		if (mem_nrefs(xconn->tc) <= refc_idle(xconn) &&
			now > xconn->created + 60) {
			restund_debug("tcp: closing unused connection\n");
			mem_deref(xconn);
		}
	};

	conn = mem_zalloc(sizeof(*conn), conn_destructor);
	if (!conn) {
		err = ENOMEM;
		goto out;
	}

	list_append(&tcl, &conn->le, conn);
	conn->created = now;
	conn->paddr = *peer;

	err = tcp_accept(&conn->tc, tl->ts, NULL, tcp_recv, tcp_close, conn);
	if (err)
		goto out;

	tcp_conn_txqsz_set(conn->tc, TCP_MAX_TXQSZ);

	err = tcp_conn_local_get(conn->tc, &conn->laddr);
	if (err)
		goto out;

#ifdef USE_TLS
	if (tl->tls) {
		err = tls_start_tcp(&conn->tlsc, tl->tls, conn->tc, 0);
		if (err)
			goto out;
	}
#endif

 out:
	if (err) {
		restund_warning("tcp: unable to accept: %m\n", err);
		tcp_reject(tl->ts);
		mem_deref(conn);
	}
}


static void status_handler(struct mbuf *mb)
{
	const time_t now = time(NULL);
	struct le *le;

	for (le=tcl.head; le; le=le->next) {

		const struct conn *conn = le->data;

		(void)mbuf_printf(mb, "%J - %J %llis\n",
				  &conn->laddr, &conn->paddr,
				  now - conn->created);
	}
}


static void lstnr_destructor(void *arg)
{
	struct tcp_lstnr *tl = arg;

	list_unlink(&tl->le);
	mem_deref(tl->ts);
	mem_deref(tl->tls);
}


static int listen_handler(const struct pl *val, void *arg)
{
	struct tcp_lstnr *tl = NULL;
	bool tls = *((bool *)arg);
	int err = ENOMEM;
	struct pl ap;

	tl = mem_zalloc(sizeof(*tl), lstnr_destructor);
	if (!tl) {
		restund_warning("tcp listen error: %m\n", err);
		goto out;
	}

	list_append(&lstnrl, &tl->le, tl);

	if (tls) {
#ifdef USE_TLS
		char certpath[1024];
		struct pl cert;

		if (re_regex(val->p, val->l, "[^,]+,[^]+", &ap, &cert)) {
			restund_warning("bad tls_listen directive: '%r'\n",
					val);
			err = EINVAL;
			goto out;
		}

		(void)pl_strcpy(&cert, certpath, sizeof(certpath));

		err = tls_alloc(&tl->tls, TLS_METHOD_SSLV23, certpath, NULL);
		if (err) {
			restund_warning("tls error: %m\n", err);
			goto out;
		}
#else
		restund_warning("tls not supported\n");
		err = EPROTONOSUPPORT;
		goto out;
#endif
	}
	else {
		ap = *val;
	}

	err = sa_decode(&tl->bnd_addr, ap.p, ap.l);
	if (err || sa_is_any(&tl->bnd_addr) || !sa_port(&tl->bnd_addr)) {
		restund_warning("bad %s_listen directive: '%r'\n",
				tls ? "tls" : "tcp", val);
		err = EINVAL;
		goto out;
	}

	err = tcp_listen(&tl->ts, &tl->bnd_addr, tcp_conn_handler, tl);
	if (err) {
		restund_warning("tcp error: %m\n", err);
		goto out;
	}

	restund_debug("%s listen: %J\n", tl->tls ? "tls" : "tcp",
		      &tl->bnd_addr);

 out:
	if (err)
		mem_deref(tl);

	return err;
}


static struct restund_cmdsub cmd_tcp = {
	.cmdh = status_handler,
	.cmd  = "tcp",
};


int restund_tcp_init(void)
{
	bool tls;
	int err;

	list_init(&lstnrl);
	list_init(&tcl);

	restund_cmd_subscribe(&cmd_tcp);

	/* tcp config */
	tls = false;

	err = conf_apply(restund_conf(), "tcp_listen", listen_handler, &tls);
	if (err)
		goto out;

	tls = true;

	err = conf_apply(restund_conf(), "tls_listen", listen_handler, &tls);
	if (err)
		goto out;

 out:
	if (err)
		restund_tcp_close();

	return err;
}


void restund_tcp_close(void)
{
	restund_cmd_unsubscribe(&cmd_tcp);
	list_flush(&lstnrl);
	list_flush(&tcl);
}


struct tcp_sock *restund_tcp_socket(struct sa *sa, const struct sa *orig,
				    bool ch_ip, bool ch_port)
{
	struct le *le = list_head(&lstnrl);

	while (le) {
		struct tcp_lstnr *tl = le->data;
		le = le->next;

		if (ch_ip && sa_cmp(orig, &tl->bnd_addr, SA_ADDR))
			continue;

		if (ch_port && (sa_port(orig) == sa_port(&tl->bnd_addr)))
			continue;

		sa_cpy(sa, &tl->bnd_addr);
		return tl->ts;
	}

	return NULL;
}
