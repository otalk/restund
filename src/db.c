/**
 * @file db.c Server Database
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <re.h>
#include <restund.h>
#include "stund.h"


struct account {
	struct le he;
	char *username;
	uint8_t ha1[MD5_SIZE];
};


struct traffic {
	struct le le;
	struct restund_trafstat ts;
	struct sa cli;
	struct sa relay;
	struct sa peer;
	char *username;
	time_t start;
	time_t end;
};


static struct {
	struct {
		pthread_mutex_t mutex;
		struct hash *ht;
		uint32_t syncint;
	} cred;
	struct {
		struct list fifo;
		pthread_mutex_t mutex;
		pthread_cond_t cond;
	} traffic;
	pthread_t thread;
	char realm[256];
	struct restund_db *db;
	bool quit;
	bool run;
} database = {
	.cred = {
		  .mutex   = PTHREAD_MUTEX_INITIALIZER,
		  .ht      = NULL,
		  .syncint = 3600,
	},
	.traffic = {
		  .mutex = PTHREAD_MUTEX_INITIALIZER,
		  .cond  = PTHREAD_COND_INITIALIZER,
	},
	.thread = 0,
	.realm  = "myrealm",
	.db     = NULL,
	.quit   = false,
	.run	= false,
};


static bool hash_cmp_handler(struct le *le, void *arg)
{
	const struct account *acc = le->data;
	const char *username = arg;

	return !strcmp(acc->username, username);
}


static void account_destructor(void *arg)
{
	struct account *acc = arg;

	acc->username = mem_deref(acc->username);
}


static int account_handler(const char *username, const char *ha1, void *arg)
{
	struct hash *ht = arg;
	struct account *acc;
	int err = ENOMEM;
	size_t len;

	acc = mem_zalloc(sizeof(struct account), account_destructor);
	if (!acc)
		goto out;

	len = strlen(username);

	acc->username = mem_alloc(len + 1, NULL);
	if (!acc->username)
		goto out;

	memcpy(acc->username, username, len + 1);

	err = str_hex(acc->ha1, MD5_SIZE, ha1);
	if (err)
		goto out;

	hash_append(ht, hash_joaat_str(acc->username), &acc->he, acc);

	err = 0;

 out:
	if (err)
		mem_deref(acc);

	return err;
}


static int sync_credentials(void)
{
	struct hash *ht = NULL, *ht_old;
	uint32_t n, x, sz;
	int err = 0;

	if (!database.db || !database.db->allh || !database.db->cnth)
		goto out;

	err = database.db->cnth(database.realm, &n);
	if (err) {
		restund_warning("database sync error (cnt): %m\n", err);
		goto out;
	}

	for (x=2; (uint32_t)1<<x<n; x++);
	sz = 1<<x;

	err = hash_alloc(&ht, sz);
	if (err) {
		restund_warning("database: unable to create hashtable: %m\n",
				err);
		goto out;
	}

	err = database.db->allh(database.realm, account_handler, ht);
	if (err) {
		restund_warning("database sync error (all): %m\n", err);
		goto out;
	}

	pthread_mutex_lock(&database.cred.mutex);
	ht_old = database.cred.ht;
	database.cred.ht = ht;
	pthread_mutex_unlock(&database.cred.mutex);

	ht = ht_old;

	restund_debug("database successfully synced (n=%u hashsize=%u)\n",
		      n, sz);

 out:
	hash_flush(ht);
	mem_deref(ht);

	return err;
}


static int save_traffic_records(void)
{
	int err = 0;

	for (;;) {
		struct traffic *trf;

		pthread_mutex_lock(&database.traffic.mutex);

		trf = list_ledata(list_head(&database.traffic.fifo));
		if (!trf) {
			pthread_mutex_unlock(&database.traffic.mutex);
			break;
		}

		list_unlink(&trf->le);
		pthread_mutex_unlock(&database.traffic.mutex);

		/* database insert */
		if (database.db && database.db->tlogh)
			err = database.db->tlogh(trf->username, &trf->cli,
						 &trf->relay, &trf->peer,
						 database.realm,
						 trf->start, trf->end,
						 &trf->ts);

		if (err) {
			restund_warning("error writing traffic record;"
					" retry later\n");
			pthread_mutex_lock(&database.traffic.mutex);
			list_prepend(&database.traffic.fifo, &trf->le, trf);
			pthread_mutex_unlock(&database.traffic.mutex);
			break;
		}

		mem_deref(trf);
	}

	return err;
}


static void gettimespec(struct timespec *ts, uint32_t offset)
{
	struct timeval tv;

	(void)gettimeofday(&tv, NULL);

	ts->tv_sec  = tv.tv_sec + offset;
	ts->tv_nsec = tv.tv_usec * 1000;
}


static void *database_thread(void *arg)
{
	struct timespec ts;
	int err = 0;
	(void)arg;

	gettimespec(&ts, 0);

	for (;;) {
		bool quit;

		pthread_mutex_lock(&database.traffic.mutex);
		quit = database.quit;
		if (!quit) {
			err = pthread_cond_timedwait(&database.traffic.cond,
						     &database.traffic.mutex,
						     &ts);
			quit = database.quit;
		}
		pthread_mutex_unlock(&database.traffic.mutex);

		(void)save_traffic_records();

		if (quit)
			break;

		if (err != ETIMEDOUT)
			continue;

		(void)sync_credentials();
		gettimespec(&ts, database.cred.syncint);
	}

	restund_debug("database thread exit\n");

	return NULL;
}


static void traffic_destructor(void *arg)
{
	struct traffic *trf = arg;

	trf->username = mem_deref(trf->username);
}


int restund_log_traffic(const char *username, const struct sa *cli,
			const struct sa *relay, const struct sa *peer,
			time_t start, time_t end,
			const struct restund_trafstat *ts)
{
	struct traffic *trf = NULL;
	int err = ENOMEM;

	if (!cli || !relay || !peer || !ts)
		return EINVAL;

	if (!database.run || !database.db || !database.db->tlogh)
		return 0;

	trf = mem_zalloc(sizeof(struct traffic), traffic_destructor);
	if (!trf)
		goto out;

	err = str_dup(&trf->username, username ? username : "");
	if (err)
		goto out;

	trf->cli   = *cli;
	trf->relay = *relay;
	trf->peer  = *peer;
	trf->start = start;
	trf->end   = end;
	trf->ts    = *ts;

	pthread_mutex_lock(&database.traffic.mutex);
	list_append(&database.traffic.fifo, &trf->le, trf);
	pthread_cond_signal(&database.traffic.cond);
	pthread_mutex_unlock(&database.traffic.mutex);

	err = 0;
out:
	if (err)
		mem_deref(trf);

	return err;
}


int restund_get_ha1(const char *username, uint8_t *ha1)
{
	struct account *acc;
	int err = ENOENT;

	if (!username || !ha1)
		return EINVAL;

	if (!database.run)
		return ENOENT;

	pthread_mutex_lock(&database.cred.mutex);

	acc = list_ledata(hash_lookup(database.cred.ht,
				      hash_joaat_str(username),
				      hash_cmp_handler, (void *)username));
	if (!acc)
		goto out;

	memcpy(ha1, acc->ha1, MD5_SIZE);

	err = 0;
 out:
	pthread_mutex_unlock(&database.cred.mutex);

	return err;
}


const char *restund_realm(void)
{
	return database.realm;
}


void restund_db_set_handler(struct restund_db *db)
{
	database.db = db;
}


int restund_db_init(void)
{
	int err;

	/* realm config */
	(void)conf_get_str(restund_conf(), "realm", database.realm,
			   sizeof(database.realm));

	/* syncinterval config */
	(void)conf_get_u32(restund_conf(), "syncinterval",
			   &database.cred.syncint);

	if (!database.db)
		return 0;

	err = pthread_create(&database.thread, NULL, database_thread, NULL);
	if (err) {
		restund_warning("database thread error: %m\n", err);
		return err;
	}

	database.run = true;

	restund_debug("database: realm is '%s', sync interval is %u secs\n",
		      database.realm, database.cred.syncint);

	return 0;
}


void restund_db_close(void)
{
	struct hash *ht;

	if (database.run) {
		pthread_mutex_lock(&database.traffic.mutex);
		database.quit = true;
		pthread_cond_signal(&database.traffic.cond);
		pthread_mutex_unlock(&database.traffic.mutex);

		pthread_join(database.thread, NULL);
		database.run = false;
	}

	pthread_mutex_lock(&database.traffic.mutex);
	list_flush(&database.traffic.fifo);
	list_init(&database.traffic.fifo);
	pthread_mutex_unlock(&database.traffic.mutex);

	pthread_mutex_lock(&database.cred.mutex);
	ht = database.cred.ht;
	database.cred.ht = NULL;
	pthread_mutex_unlock(&database.cred.mutex);

	if (!ht)
		return;

	hash_flush(ht);
	mem_deref(ht);
}
