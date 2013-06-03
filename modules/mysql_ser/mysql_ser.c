/**
 * @file mysql_ser.c MySQL Database Backend
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <stdlib.h>
#include <string.h>
#include <mysql/mysql.h>
#include <mysql/errmsg.h>
#include <re.h>
#include <restund.h>


#ifndef ER_NO_REFERENCED_ROW_2
#define ER_NO_REFERENCED_ROW_2 1452
#endif


static struct {
	char host[128];
	char user[128];
	char pass[128];
	char db[128];
	MYSQL mysql;
	uint32_t version;  /* SER Version, e.g. 1, 2 or 3 */
} my;


static int myconnect(void)
{
	mysql_init(&my.mysql);

	if (!mysql_real_connect(&my.mysql, my.host, my.user, my.pass, my.db,
				0, NULL, 0))
		return(ECONNREFUSED);

	restund_debug("mysql: connected (server %s at %s)\n",
		      mysql_get_server_info(&my.mysql),
		      mysql_get_host_info(&my.mysql));

	return 0;
}


static int query(MYSQL_RES **res, const char *fmt, ...)
{
	bool failed = false;
	char qstr[1024];
	va_list ap;
	int err;

	va_start(ap, fmt);
	err = re_vsnprintf(qstr, sizeof(qstr), fmt, ap);
	va_end(ap);

	if (err < 0)
		return -1;

 retry:
	if (!mysql_query(&my.mysql, qstr)) {
		if (res) {
			*res = mysql_store_result(&my.mysql);
			if (!(*res))
				return ENOMEM;
		}

		return 0;
	}

	if (failed)
		return -1;

	switch (mysql_errno(&my.mysql)) {

	case CR_SERVER_GONE_ERROR:
	case CR_SERVER_LOST:
		failed = true;
		mysql_close(&my.mysql);

		err = myconnect();
		if (err) {
			restund_error("mysql: %s\n", mysql_error(&my.mysql));
			break;
		}

		goto retry;

	default:
		err = -1;
		break;
	}

	return err;
}


static int accounts_getall(const char *realm, restund_db_account_h *acch,
			   void *arg)
{
	MYSQL_RES *res;
	int err = 0;

	if (!realm || !acch)
		return EINVAL;

	switch (my.version) {

	case 2:
		err = query(&res,
			    "SELECT auth_username, ha1 "
			    "FROM credentials WHERE realm = '%s';",
			    realm);
		break;

	default:
		err = query(&res,
			    "SELECT username, ha1 "
			    "FROM subscriber where domain = '%s';",
			    realm);
		break;
	}

	if (err) {
		restund_warning("mysql: unable to select accounts: %s\n",
				mysql_error(&my.mysql));
		return err;
	}

	for (;!err;) {
		MYSQL_ROW row;

		row = mysql_fetch_row(res);
		if (!row)
			break;

		err = acch(row[0] ? row[0] : "", row[1] ? row[1] : "", arg);
	}

	mysql_free_result(res);

	return err;
}


static int accounts_count(const char *realm, uint32_t *n)
{
	MYSQL_RES *res;
	MYSQL_ROW row;
	int err = 0;

	if (!realm || !n)
		return EINVAL;

	switch (my.version) {

	case 2:
		err = query(&res,
			    "SELECT COUNT(*) "
			    "FROM credentials WHERE realm = '%s';",
			    realm);
		break;

	default:
		err = query(&res,
			    "SELECT COUNT(*) "
			    "FROM subscriber where domain = '%s';",
			    realm);
		break;
	}

	if (err) {
		restund_warning("mysql: unable to select nr of accounts: %s\n",
				mysql_error(&my.mysql));
		return err;
	}

	row = mysql_fetch_row(res);
	if (row)
		*n = atoi(row[0]);
	else
		err = ENOENT;

	mysql_free_result(res);

	return err;
}


static int module_init(void)
{
	static struct restund_db db = {
		.allh  = accounts_getall,
		.cnth  = accounts_count,
		.tlogh = NULL,
	};

	conf_get_str(restund_conf(), "mysql_host", my.host, sizeof(my.host));
	conf_get_str(restund_conf(), "mysql_user", my.user, sizeof(my.user));
	conf_get_str(restund_conf(), "mysql_pass", my.pass, sizeof(my.pass));
	conf_get_str(restund_conf(), "mysql_db",   my.db,   sizeof(my.db));
	conf_get_u32(restund_conf(), "mysql_ser", &my.version);

	if (myconnect()) {
		restund_error("mysql: %s\n", mysql_error(&my.mysql));
	}

	restund_db_set_handler(&db);

	return 0;
}


static int module_close(void)
{
	mysql_close(&my.mysql);

	restund_debug("mysql: module closed\n");

	return 0;
}


const struct mod_export exports = {
	.name = "mysql_ser",
	.type = "database client",
	.init = module_init,
	.close = module_close,
};
