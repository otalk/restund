/**
 * @file restund.h Module Interface
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <time.h>

/* cmd */

typedef void(restund_cmd_h)(struct mbuf *mb);

struct restund_cmdsub {
	struct le le;
	restund_cmd_h *cmdh;
	const char *cmd;
};

void restund_cmd(const struct pl *cmd, struct mbuf *mb);
void restund_cmd_subscribe(struct restund_cmdsub *cs);
void restund_cmd_unsubscribe(struct restund_cmdsub *cs);


/* log */

enum {
	RESTUND_DEBUG = 0,
	RESTUND_INFO,
	RESTUND_WARNING,
	RESTUND_ERROR,
};

typedef void(restund_log_h)(uint32_t level, const char *msg);

struct restund_log {
	struct le le;
	restund_log_h *h;
};

void restund_log_register_handler(struct restund_log *log);
void restund_log_unregister_handler(struct restund_log *log);
void restund_log_enable_debug(bool enable);
void restund_log_enable_stderr(bool enable);
void restund_vlog(uint32_t level, const char *fmt, va_list ap);
void restund_log(uint32_t level, const char *fmt, ...);
void restund_debug(const char *fmt, ...);
void restund_info(const char *fmt, ...);
void restund_warning(const char *fmt, ...);
void restund_error(const char *fmt, ...);


/* stun */

extern const char *restund_software;

struct restund_msgctx {
	struct stun_unknown_attr ua;
	uint8_t *key;
	uint32_t keylen;
	bool fp;
};


typedef bool(restund_stun_msg_h)(struct restund_msgctx *ctx,
				 int proto, void *sock,
				 const struct sa *src, const struct sa *dst,
				 const struct stun_msg *msg);
typedef bool(restund_stun_raw_h)(int proto,
				 const struct sa *src, const struct sa *dst,
				 struct mbuf *mb);

struct restund_stun {
	struct le le;
	restund_stun_msg_h *reqh;
	restund_stun_msg_h *indh;
	restund_stun_raw_h *rawh;
};

void restund_stun_register_handler(struct restund_stun *stun);
void restund_stun_unregister_handler(struct restund_stun *stun);


/* database */
struct restund_trafstat {
	uint64_t pktc_tx;
	uint64_t pktc_rx;
	uint64_t bytc_tx;
	uint64_t bytc_rx;
};


typedef int(restund_db_account_h)(const char *username, const char *ha1,
				  void *arg);
typedef int(restund_db_account_all_h)(const char *realm,
				      restund_db_account_h *acch, void *arg);
typedef int(restund_db_account_cnt_h)(const char *realm, uint32_t *n);
typedef int(restund_db_traffic_log_h)(const char *username,
				      const struct sa *cli,
				      const struct sa *relay,
				      const struct sa *peer,
				      const char *realm,
				      time_t start, time_t end,
				      const struct restund_trafstat *ts);

struct restund_db {
	struct le le;
	restund_db_account_all_h *allh;
	restund_db_account_cnt_h *cnth;
	restund_db_traffic_log_h *tlogh;
};

int  restund_log_traffic(const char *username, const struct sa *cli,
			 const struct sa *relay, const struct sa *peer,
			 time_t start, time_t end,
			 const struct restund_trafstat *ts);
int  restund_get_ha1(const char *username, uint8_t *ha1);
const char *restund_realm(void);
void restund_db_set_handler(struct restund_db *db);


/* div */

struct conf *restund_conf(void);
struct udp_sock *restund_udp_socket(struct sa *sa, const struct sa *orig,
				    bool ch_ip, bool ch_port);
struct tcp_sock *restund_tcp_socket(struct sa *sa, const struct sa *orig,
				    bool ch_ip, bool ch_port);
