/**
 * @file httpd.c  http server
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <re.h>
#include "httpd.h"


struct conn {
	struct le le;
	struct tmr tmr;
	struct httpd *httpd;
	struct tcp_conn *tc;
};


struct httpd {
	struct list connl;
	struct tcp_sock *ts;
	httpd_h *h;
};


static void timeout_handler(void *arg)
{
	struct conn *conn = arg;

	conn = mem_deref(conn);
}


static void estab_handler(void *arg)
{
	(void)arg;
}


static void recv_handler(struct mbuf *mbrx, void *arg)
{
	struct mbuf *mb = NULL, *body = NULL;
	struct conn *conn = arg;
	struct pl met, url, ver;
	int err = 0;

	if (re_regex((char *)mbrx->buf, mbrx->end,
		     "[^ ]+ [^ ]+ HTTP/[^\r\n]+\r\n", &met, &url, &ver)) {
		re_printf("invalid http request\n");
		goto out;
	}

	mb   = mbuf_alloc(512);
	body = mbuf_alloc(8192);
	if (!mb || !body)
		goto out;

	conn->httpd->h(&url, body);

	err |= mbuf_printf(mb, "HTTP/%r 200 OK\r\n", &ver);
	err |= mbuf_write_str(mb, "Content-Type: text/html;charset=UTF-8\r\n");
	err |= mbuf_printf(mb, "Content-Length: %u\r\n\r\n", body->end);
	err |= mbuf_write_mem(mb, body->buf, body->end);
	if (err)
		goto out;

	mb->pos = 0;
	tcp_send(conn->tc, mb);

	tmr_start(&conn->tmr, 600 * 1000, timeout_handler, conn);
 out:
	mem_deref(mb);
	mem_deref(body);
}


static void close_handler(int err, void *arg)
{
	struct conn *conn = arg;
	(void)err;

	conn = mem_deref(conn);
}


static void conn_destructor(void *arg)
{
	struct conn *conn = arg;

	tmr_cancel(&conn->tmr);
	list_unlink(&conn->le);
	conn->tc = mem_deref(conn->tc);
}


static void connect_handler(const struct sa *peer, void *arg)
{
	struct httpd *httpd = arg;
	struct conn *conn = NULL;
	int err = ENOMEM;

	(void)peer;

	conn = mem_zalloc(sizeof(struct conn), conn_destructor);
	if (!conn)
		goto out;

	conn->httpd = httpd;
	list_append(&httpd->connl, &conn->le, conn);

	err = tcp_accept(&conn->tc, httpd->ts, estab_handler,
			 recv_handler, close_handler, conn);
	if (err)
		goto out;

	tmr_start(&conn->tmr, 5000, timeout_handler, conn);

 out:
	if (err) {
		mem_deref(conn);
		tcp_reject(httpd->ts);
	}
}


static void httpd_destructor(void *arg)
{
	struct httpd *httpd = arg;

	list_flush(&httpd->connl);
	httpd->ts = mem_deref(httpd->ts);
}


int httpd_alloc(struct httpd **httpdpp, struct sa *laddr, httpd_h *h)
{
	struct httpd *httpd = NULL;
	int err = ENOMEM;

	if (!httpdpp || !laddr || !h)
		return EINVAL;

	httpd = mem_zalloc(sizeof(struct httpd), httpd_destructor);
	if (!httpd)
		goto out;

	err = tcp_listen(&httpd->ts, laddr, connect_handler, httpd);
	if (err)
		goto out;

	httpd->h = h;
	*httpdpp = httpd;
	err = 0;

 out:
	if (err)
		mem_deref(httpd);

	return err;
}
