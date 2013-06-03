/**
 * @file syslog.c Syslog
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <syslog.h>
#include <re.h>
#include <restund.h>


static const int lmap[] = { LOG_DEBUG, LOG_INFO, LOG_WARNING, LOG_ERR };


static void log_handler(uint32_t level, const char *msg)
{
	syslog(lmap[MIN(level, sizeof(lmap - 1))], "%s", msg);
}


static struct restund_log lg = {
	.h = log_handler,
};


static int module_init(void)
{
	uint32_t facility = LOG_DAEMON;

	conf_get_u32(restund_conf(), "syslog_facility", &facility);

	openlog("restund", LOG_NDELAY | LOG_PID, facility);

	restund_log_register_handler(&lg);

	restund_debug("syslog: module loaded facility=%u\n", facility);

	return 0;
}


static int module_close(void)
{
	restund_debug("syslog: module closed\n");

	restund_log_unregister_handler(&lg);

	closelog();

	return 0;
}


const struct mod_export exports = {
	.name = "syslog",
	.type = "logger",
	.init = module_init,
	.close = module_close,
};
