/**
 * @file influxdb.c  influxdb statistics module
 *
 * Copyright (C) 2014 andyet LLC and otalk contributors
 */

#include <string.h>
#include <re.h>
#include <restund.h>
#include <unistd.h>


static struct {
    struct tmr tmr;
    uint32_t freq;

	struct sa dest_udp;
    char identifier[512];
} stuff;

struct turnstats {
    time_t ts;
	long long unsigned bytec_tx;
	long long unsigned bytec_rx;
    long long unsigned bytec;
	long long unsigned allocc_tot;
	unsigned allocc_cur;
};

static struct turnstats tstats;


static void tic(void *arg) {
    struct cpustats {
        int usr;
        int sys;
    } cpustats;
	const time_t now = time(NULL);

    struct mbuf *mb;
	struct pl cmd;
    char buf[4096];
    struct turnstats oldturn;

	tmr_start(&stuff.tmr, stuff.freq * 1000, tic, NULL);

    mb = mbuf_alloc(4096);
    // get cpu stats
    pl_set_str(&cmd, "cpuusage");
	restund_cmd(&cmd, mb);
    mbuf_write_u8(mb, 0);
    mbuf_set_pos(mb, 0);
    mbuf_read_str(mb, buf, sizeof(buf));
    sscanf(buf, "usr %d\nsys %d\n", &cpustats.usr, &cpustats.sys);

    // get turn stats
    mbuf_reset(mb);
    pl_set_str(&cmd, "turnstats");
	restund_cmd(&cmd, mb);
    mbuf_write_u8(mb, 0);
    mbuf_set_pos(mb, 0);
    mbuf_read_str(mb, buf, sizeof(buf));
    memcpy(&oldturn, &tstats, sizeof(oldturn));
    sscanf(buf, 
           "allocs_cur %u\n"
           "allocs_tot %llu\n"
           "bytes_tx %llu\n"
           "bytes_rx %llu\n"
           "bytes_tot %llu\n",
           &tstats.allocc_cur,
           &tstats.allocc_tot,
           &tstats.bytec_rx,
           &tstats.bytec_tx,
           &tstats.bytec);
    tstats.ts = now;

    // contains negative difference, must be multiplied by -1
    // (or divived by negative time diff)
    oldturn.ts -= tstats.ts;
    oldturn.allocc_cur = tstats.allocc_cur;
    oldturn.allocc_tot = tstats.allocc_tot;
    oldturn.bytec_rx -= tstats.bytec_rx;
    oldturn.bytec_tx -= tstats.bytec_tx;
    oldturn.bytec -= tstats.bytec;


    // write out stuff
    mbuf_reset(mb);
    mbuf_write_str(mb, "[{\"name\": \"restund\","
                   "\"columns\": ["
                   "\"time\", \"host\", \"utime\", \"stime\", "
                   "\"allocs_cur\", \"bytes_rx\", \"bytes_tx\", \"bytes_tot\""
                   "],");
    mbuf_printf(mb, "\"points\": [[%ld, \"%s\", %d, %d, %d, %d, %d, %d]]", 
                now, stuff.identifier,
                cpustats.usr, cpustats.sys,
                oldturn.allocc_cur,
                oldturn.bytec_rx / oldturn.ts,
                oldturn.bytec_tx / oldturn.ts,
                oldturn.bytec / oldturn.ts);
    mbuf_write_str(mb, "}]");
    mbuf_set_pos(mb, 0);

    udp_send_anon(&stuff.dest_udp, mb);
	mb = mem_deref(mb);
}


static int module_init(void)
{
	struct pl addr;
	uint32_t port;
	int err;

	restund_debug("influxdb: module loaded\n");

	/* UDP bind address */
	if (conf_get(restund_conf(), "influxdb_udp_addr", &addr))
		pl_set_str(&addr, "127.0.0.1");

	if (conf_get_u32(restund_conf(), "influxdb_udp_port", &port))
		port = 5587;

	if (conf_get_u32(restund_conf(), "influxdb_frequency", &stuff.freq))
		stuff.freq = 15;

    if (conf_get_str(restund_conf(), "influxdb_host_identifier", stuff.identifier, sizeof(stuff.identifier)))
        strcpy(stuff.identifier, "unknown");

	err = sa_set(&stuff.dest_udp, &addr, port);
	if (err) {
		restund_error("status: bad udp bind address: %r:%u",
			      &addr, port);
		goto out;
	}

    tstats.ts = time(NULL);
    tstats.bytec_tx = 0;
    tstats.bytec_rx = 0;
    tstats.bytec = 0;
    tstats.allocc_tot = 0;
    tstats.allocc_cur = 0;

    /* start doing stuff */
	tmr_start(&stuff.tmr, stuff.freq * 1000, tic, NULL);

 out:
	if (err) {
	}

	return err;
	return 0;
}


static int module_close(void)
{
	restund_debug("influxdb: module closed\n");

	tmr_cancel(&stuff.tmr);
	return 0;
}


const struct mod_export exports = {
	.name  = "influxdb",
	.type  = "stun",
	.init  = module_init,
	.close = module_close
};
