/**
 * @file auth.c Implements STUN Authentication and Message-Integrity Mechanisms
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <string.h>
#include <time.h>
#include <re.h>
#include <restund.h>


enum {
	NONCE_EXPIRY   = 3600,
	NONCE_MAX_SIZE = 48,
	NONCE_MIN_SIZE = 33,
};


static struct {
	uint32_t nonce_expiry;
	uint64_t secret;
} auth;


static const char *mknonce(char *nonce, time_t now, const struct sa *src)
{
	uint8_t key[MD5_SIZE];
	uint64_t nv[3];

	nv[0] = now;
	nv[1] = auth.secret;
	nv[2] = sa_hash(src, SA_ADDR);

	md5((uint8_t *)nv, sizeof(nv), key);

	(void)re_snprintf(nonce, NONCE_MAX_SIZE + 1, "%w%llx",
			  key, sizeof(key), nv[0]);

	return nonce;
}


static bool nonce_validate(char *nonce, time_t now, const struct sa *src)
{
	uint8_t nkey[MD5_SIZE], ckey[MD5_SIZE];
	uint64_t nv[3];
	struct pl pl;
	int64_t age;
	unsigned i;

	pl.p = nonce;
	pl.l = str_len(nonce);

	if (pl.l < NONCE_MIN_SIZE || pl.l > NONCE_MAX_SIZE) {
		restund_info("auth: bad nonce length (%zu)\n", pl.l);
		return false;
	}

	for (i=0; i<sizeof(nkey); i++) {
		nkey[i]  = ch_hex(*pl.p++) << 4;
		nkey[i] += ch_hex(*pl.p++);
		pl.l -= 2;
	}

	nv[0] = pl_x64(&pl);
	nv[1] = auth.secret;
	nv[2] = sa_hash(src, SA_ADDR);

	md5((uint8_t *)nv, sizeof(nv), ckey);

	if (memcmp(nkey, ckey, MD5_SIZE)) {
		restund_debug("auth: invalid nonce (%j)\n", src);
		return false;
	}

	age = now - nv[0];

	if (age < 0 || age > auth.nonce_expiry) {
		restund_debug("auth: nonce expired, age: %lli secs\n", age);
		return false;
	}

	return true;
}


static bool request_handler(struct restund_msgctx *ctx, int proto, void *sock,
			    const struct sa *src, const struct sa *dst,
			    const struct stun_msg *msg)
{
	struct stun_attr *mi, *user, *realm, *nonce;
	const time_t now = time(NULL);
	char nstr[NONCE_MAX_SIZE + 1];
	int err;
	(void)dst;

	if (ctx->key)
		return false;

	mi    = stun_msg_attr(msg, STUN_ATTR_MSG_INTEGRITY);
	user  = stun_msg_attr(msg, STUN_ATTR_USERNAME);
	realm = stun_msg_attr(msg, STUN_ATTR_REALM);
	nonce = stun_msg_attr(msg, STUN_ATTR_NONCE);

	if (!mi) {
		err = stun_ereply(proto, sock, src, 0, msg,
				  401, "Unauthorized",
				  NULL, 0, ctx->fp, 3,
				  STUN_ATTR_REALM, restund_realm(),
				  STUN_ATTR_NONCE, mknonce(nstr, now, src),
				  STUN_ATTR_SOFTWARE, restund_software);
		goto unauth;
	}

	if (!user || !realm || !nonce) {
		err = stun_ereply(proto, sock, src, 0, msg,
				  400, "Bad Request",
				  NULL, 0, ctx->fp, 1,
				  STUN_ATTR_SOFTWARE, restund_software);
		goto unauth;
	}

	if (!nonce_validate(nonce->v.nonce, now, src)) {
		err = stun_ereply(proto, sock, src, 0, msg,
				  438, "Stale Nonce",
				  NULL, 0, ctx->fp, 3,
				  STUN_ATTR_REALM, restund_realm(),
				  STUN_ATTR_NONCE, mknonce(nstr, now, src),
				  STUN_ATTR_SOFTWARE, restund_software);
		goto unauth;
	}

	ctx->key = mem_alloc(MD5_SIZE, NULL);
	if (!ctx->key) {
		restund_warning("auth: can't to allocate memory for MI key\n");
		err = stun_ereply(proto, sock, src, 0, msg,
				  500, "Server Error",
				  NULL, 0, ctx->fp, 1,
				  STUN_ATTR_SOFTWARE, restund_software);
		goto unauth;
	}

	ctx->keylen = MD5_SIZE;

	if (restund_get_ha1(user->v.username, ctx->key)) {
		restund_info("auth: unknown user '%s' (%j)\n",
			     user->v.username, src);
		err = stun_ereply(proto, sock, src, 0, msg,
				  401, "Unauthorized",
				  NULL, 0, ctx->fp, 3,
				  STUN_ATTR_REALM, restund_realm(),
				  STUN_ATTR_NONCE, mknonce(nstr, now, src),
				  STUN_ATTR_SOFTWARE, restund_software);
		goto unauth;
	}

	if (stun_msg_chk_mi(msg, ctx->key, ctx->keylen)) {
		restund_info("auth: bad password for user '%s' (%j)\n",
			     user->v.username, src);
		err = stun_ereply(proto, sock, src, 0, msg,
				  401, "Unauthorized",
				  NULL, 0, ctx->fp, 3,
				  STUN_ATTR_REALM, restund_realm(),
				  STUN_ATTR_NONCE, mknonce(nstr, now, src),
				  STUN_ATTR_SOFTWARE, restund_software);
		goto unauth;
	}

	return false;

 unauth:
	if (err) {
		restund_warning("auth reply error: %m\n", err);
	}

	return true;
}


static struct restund_stun stun = {
	.reqh = request_handler
};


static int module_init(void)
{
	auth.nonce_expiry = NONCE_EXPIRY;
	auth.secret = rand_u64();

	conf_get_u32(restund_conf(), "auth_nonce_expiry", &auth.nonce_expiry);

	restund_stun_register_handler(&stun);

	restund_debug("auth: module loaded (nonce_expiry=%us)\n",
		      auth.nonce_expiry);

	return 0;
}


static int module_close(void)
{
	restund_stun_unregister_handler(&stun);

	restund_debug("auth: module closed\n");

	return 0;
}


const struct mod_export exports = {
	.name  = "auth",
	.type  = "stun",
	.init  = module_init,
	.close = module_close
};
