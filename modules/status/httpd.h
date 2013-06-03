/**
 * @file httpd.c  http server interface
 *
 * Copyright (C) 2010 Creytiv.com
 */

typedef void(httpd_h)(const struct pl *uri, struct mbuf *mb);

struct httpd;

int httpd_alloc(struct httpd **httpd, struct sa *laddr, httpd_h *h);
