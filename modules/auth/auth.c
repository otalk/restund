/**
 * @file auth.c Implements STUN Authentication and Message-Integrity Mechanisms
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <re.h>
/*#include <re_hmac.h>*/
#include <restund.h>

#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

enum {
	NONCE_EXPIRY   = 3600,
	NONCE_MAX_SIZE = 48,
	NONCE_MIN_SIZE = 33,
};


static struct {
	uint32_t nonce_expiry;
	uint64_t secret;
	char sharedsecret[256];
	size_t sharedsecret_length;
	char sharedsecret2[256];
	size_t sharedsecret2_length;
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

/* shared secret authentication as described in 
 * http://tools.ietf.org/html/draft-uberti-rtcweb-turn-rest-00
 */
static bool sharedsecret_auth_check_timestamp(const struct stun_attr *user, const time_t now) 
{
    long ts = 0;
    sscanf(user->v.username, "%ld:%*s", &ts);
    if (now > ts) {
        restund_debug("auth: shared secret nonce expired, ts was %ld now is %ld\n", ts, now);
        return false;
    }
    return true;
}

static bool sharedsecret_auth_calc_ha1(const struct stun_attr *user, const uint8_t *secret, const size_t secret_length, uint8_t *key) 
{
	uint8_t expected[SHA_DIGEST_LENGTH];
	char expected_base64[SHA_DIGEST_LENGTH/2*3];
	size_t b64len;

	uint8_t ha1[MD5_SIZE];
	int retval;
	if (!secret_length) {
        /*
		restund_warning("auth: calc_ha1 no secret length %s\n", secret);
        */
		return false;
	}

	hmac_sha1(secret, secret_length,
		  (uint8_t *) user->v.username, strlen(user->v.username),
		  expected, SHA_DIGEST_LENGTH);
	b64len = sizeof expected_base64;
	if ((retval = base64_encode(expected, SHA_DIGEST_LENGTH, expected_base64, &b64len)) != 0) {
		restund_warning("auth: failed to base64 encode hmac, error %d\n", retval);
		return false;	
	}
	expected_base64[b64len] = 0;
	if ((retval = md5_printf(ha1, "%s:%s:%s", user->v.username, restund_realm(), expected_base64)) != 0) {
		restund_warning("auth: failed to md5_printf ha1, error %d\n", retval);
		return false;
	}
	memcpy(key, &ha1, MD5_SIZE);
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
	if (auth.sharedsecret_length > 0 || auth.sharedsecret2_length > 0) {
		if (!((sharedsecret_auth_calc_ha1(user, (uint8_t*) auth.sharedsecret, 
                                auth.sharedsecret_length, ctx->key)
			    && !stun_msg_chk_mi(msg, ctx->key, ctx->keylen))
			|| (sharedsecret_auth_calc_ha1(user, (uint8_t*) auth.sharedsecret2,
                                   auth.sharedsecret2_length, ctx->key)
			   && !stun_msg_chk_mi(msg, ctx->key, ctx->keylen)))) {
			restund_info("auth: shared secret auth for user '%s' (%j) failed\n",
				     user->v.username, src);
			err = stun_ereply(proto, sock, src, 0, msg,
					  401, "Unauthorized",
					  NULL, 0, ctx->fp, 3,
					  STUN_ATTR_REALM, restund_realm(),
					  STUN_ATTR_NONCE, mknonce(nstr, now, src),
					  STUN_ATTR_SOFTWARE, restund_software);
			goto unauth;
		} else {
            /*
			restund_info("auth: shared secret auth for user '%s' (%j) worked\n",
				     user->v.username, src);
            */
            if (STUN_METHOD_ALLOCATE == stun_msg_method(msg) && !sharedsecret_auth_check_timestamp(user, now)) {
                restund_info("auth: shared secret auth for user '%s' expired)\n",
                         user->v.username);
                err = stun_ereply(proto, sock, src, 0, msg,
                          401, "Unauthorized",
                          NULL, 0, ctx->fp, 3,
                          STUN_ATTR_REALM, restund_realm(),
                          STUN_ATTR_NONCE, mknonce(nstr, now, src),
                          STUN_ATTR_SOFTWARE, restund_software);
                goto unauth;
            }
		}
	} else if (restund_get_ha1(user->v.username, ctx->key)) {
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

	auth.sharedsecret_length = 0;
	auth.sharedsecret2_length = 0;
    conf_get_str(restund_conf(), "auth_shared", auth.sharedsecret, sizeof(auth.sharedsecret));
    auth.sharedsecret_length = strlen(auth.sharedsecret);
    conf_get_str(restund_conf(), "auth_shared_rollover", auth.sharedsecret2, sizeof(auth.sharedsecret2));
    auth.sharedsecret2_length = strlen(auth.sharedsecret2);
    if (auth.sharedsecret_length > 0 || auth.sharedsecret2_length > 0) {
        restund_debug("auth: module loaded shared secret lengths %d and %d\n", 
                      auth.sharedsecret_length,
                      auth.sharedsecret2_length);
    }

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
