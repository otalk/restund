/**
 * @file cmd.c Server Command
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <re.h>
#include <restund.h>


static struct list csl;


void restund_cmd(const struct pl *cmd, struct mbuf *mb)
{
	bool found = false;
	struct le *le;

	if (!cmd || !mb)
		return;

	le = csl.head;

	while (le) {

		struct restund_cmdsub *cs = le->data;
		le = le->next;

		if (!cs->cmdh)
			continue;

		if (pl_strcmp(cmd, cs->cmd))
			continue;

		cs->cmdh(mb);
		found = true;
	}

	if (!found)
		(void)mbuf_printf(mb, "%r: command not found\n", cmd);
}


void restund_cmd_subscribe(struct restund_cmdsub *cs)
{
	if (!cs)
		return;

	list_append(&csl, &cs->le, cs);
}


void restund_cmd_unsubscribe(struct restund_cmdsub *cs)
{
	if (!cs)
		return;

	list_unlink(&cs->le);
}
