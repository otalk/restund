/**
 * @file status.c  Status module
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <string.h>
#include <time.h>
#include <re.h>
#include <restund.h>
#include "httpd.h"


enum {
	CHUNK_SIZE = 1024,
};


static struct {
	struct udp_sock *us;
	struct httpd *httpd;
	time_t start;
} stg;


static void server_info(struct mbuf *mb)
{
	const uint32_t uptime = (uint32_t)(time(NULL) - stg.start);

	mbuf_write_str(mb, "<table>\n");
	mbuf_write_str(mb,
		       " <tr><td>Version:</td><td>" VERSION "</td></tr>\n");
	mbuf_write_str(mb,
		       " <tr><td>Built:</td><td>" __DATE__ " " __TIME__
		       "</td></tr>\n");
	mbuf_printf(mb, " <tr><td>Uptime:</td><td>%H</td></tr>\n",
		    fmt_human_time, &uptime);
	mbuf_write_str(mb, "</table>\n");
}


static void httpd_handler(const struct pl *uri, struct mbuf *mb)
{
	struct pl cmd, params, r;
	uint32_t refresh = 0;

	if (re_regex(uri->p, uri->l, "/[^?]*[^]*", &cmd, &params))
		return;

	if (!re_regex(params.p, params.l, "[?&]1r=[0-9]+", NULL, &r))
		refresh = pl_u32(&r);

	mbuf_write_str(mb, "<html>\n<head>\n");
	mbuf_write_str(mb, " <title>Restund Server Status</title>\n");

	if (refresh)
		mbuf_printf(mb,
			    " <meta http-equiv=\"refresh\" content=\"%u\">\n",
			    refresh);

	mbuf_write_str(mb, "</head>\n<body>\n");
	mbuf_write_str(mb, "<h2>Restund Server Status</h2>\n");
	server_info(mb);
	mbuf_write_str(mb, "<hr size=\"1\"/>\n<pre>\n");
	restund_cmd(&cmd, mb);
	mbuf_write_str(mb, "</pre>\n</body>\n</html>\n");
}


static void udp_recv(const struct sa *src, struct mbuf *mbrx, void *arg)
{
	static struct pl cmd = PL("");
	static char buf[32];
	bool done = false;
	struct mbuf *mb;

	(void)arg;

	if (!re_regex((char *)mbrx->buf, mbrx->end, "[^\n]+", &cmd)) {
		cmd.l = MIN(cmd.l, sizeof(buf));
		memcpy(buf, cmd.p, cmd.l);
		cmd.p = buf;
	}

	mb = mbuf_alloc(8192);
	if (!mb)
		return;

	restund_cmd(&cmd, mb);

	mb->pos = 0;

	while (!done) {

		struct mbuf mbtx;

		mbtx.buf = mbuf_buf(mb);
		mbtx.pos = 0;
		mbtx.end = mb->buf - mbtx.buf + mb->end;

		if (mbtx.end > CHUNK_SIZE)
			mbtx.end = CHUNK_SIZE;
		else
			done = true;

		udp_send(stg.us, src, &mbtx);

		mb->pos += mbtx.end;
	}

	mb = mem_deref(mb);
}


static int module_init(void)
{
	struct sa laddr_udp, laddr_http;
	struct pl addr;
	uint32_t port;
	int err;

	/* UDP bind address */
	if (conf_get(restund_conf(), "status_udp_addr", &addr))
		pl_set_str(&addr, "127.0.0.1");

	if (conf_get_u32(restund_conf(), "status_udp_port", &port))
		port = 33000;

	err = sa_set(&laddr_udp, &addr, port);
	if (err) {
		restund_error("status: bad udp bind address: %r:%u",
			      &addr, port);
		goto out;
	}

	/* HTTP bind address */
	if (conf_get(restund_conf(), "status_http_addr", &addr))
		pl_set_str(&addr, "127.0.0.1");

	if (conf_get_u32(restund_conf(), "status_http_port", &port))
		port = 8080;

	err = sa_set(&laddr_http, &addr, port);
	if (err) {
		restund_error("status: bad http bind address: %r:%u",
			      &addr, port);
		goto out;
	}

	err = udp_listen(&stg.us, &laddr_udp, udp_recv, NULL);
	if (err) {
		restund_warning("status: udp_listen: %m\n", err);
		goto out;
	}

	err = httpd_alloc(&stg.httpd, &laddr_http, httpd_handler);
	if (err) {
		restund_warning("status: httpd: %m\n", err);
		goto out;
	}

	stg.start = time(NULL);

	restund_debug("status: module loaded (udp=%J http=%J)\n",
		      &laddr_udp, &laddr_http);

 out:
	if (err) {
		stg.us = mem_deref(stg.us);
		stg.httpd = mem_deref(stg.httpd);
	}

	return err;
}


static int module_close(void)
{
	stg.us = mem_deref(stg.us);
	stg.httpd = mem_deref(stg.httpd);

	restund_debug("status: module closed\n");

	return 0;
}


const struct mod_export exports = {
	.name  = "status",
	.type  = "status",
	.init  = module_init,
	.close = module_close
};
