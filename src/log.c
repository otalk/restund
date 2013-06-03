/**
 * @file log.c Logging
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <re.h>
#include <restund.h>


static struct {
	struct list logl;
	bool debug;
	bool stder;
} lg = {
	.logl  = LIST_INIT,
	.debug = false,
	.stder = true
};


void restund_log_register_handler(struct restund_log *log)
{
	if (!log)
		return;

	list_append(&lg.logl, &log->le, log);
}


void restund_log_unregister_handler(struct restund_log *log)
{
	if (!log)
		return;

	list_unlink(&log->le);
}


void restund_log_enable_debug(bool enable)
{
	lg.debug = enable;
}


void restund_log_enable_stderr(bool enable)
{
	lg.stder = enable;
}


void restund_vlog(uint32_t level, const char *fmt, va_list ap)
{
	char buf[4096];
	struct le *le;

	if (re_vsnprintf(buf, sizeof(buf), fmt, ap) < 0)
		return;

	if (lg.stder)
		(void)re_fprintf(stderr, "%s", buf);

	le = lg.logl.head;

	while (le) {

		struct restund_log *log = le->data;
		le = le->next;

		if (log->h)
			log->h(level, buf);
	}
}


void restund_log(uint32_t level, const char *fmt, ...)
{
	va_list ap;

	if ((RESTUND_DEBUG == level) && !lg.debug)
		return;

	va_start(ap, fmt);
	restund_vlog(level, fmt, ap);
	va_end(ap);
}


void restund_debug(const char *fmt, ...)
{
	va_list ap;

	if (!lg.debug)
		return;

	va_start(ap, fmt);
	restund_vlog(RESTUND_DEBUG, fmt, ap);
	va_end(ap);
}


void restund_info(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	restund_vlog(RESTUND_INFO, fmt, ap);
	va_end(ap);
}


void restund_warning(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	restund_vlog(RESTUND_WARNING, fmt, ap);
	va_end(ap);
}


void restund_error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	restund_vlog(RESTUND_ERROR, fmt, ap);
	va_end(ap);
}
