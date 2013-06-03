/**
 * @file stund.h Internal interface
 *
 * Copyright (C) 2010 Creytiv.com
 */

/* udp */
int  restund_udp_init(void);
void restund_udp_close(void);

/* tcp */
int  restund_tcp_init(void);
void restund_tcp_close(void);

/* stun */
void restund_process_msg(int proto, void *sock,
			 const struct sa *src, const struct sa *dst,
			 struct mbuf *mb);

/* database */
int  restund_db_init(void);
void restund_db_close(void);
