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

struct reqstats {
    time_t ts;
	long unsigned n_bind_req;
	long unsigned n_alloc_req;
	long unsigned n_refresh_req;
	long unsigned n_chanbind_req;
	long unsigned n_unk_req;
};
static struct reqstats rstats;

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
    struct reqstats oldreq;
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

    // get request stats
    mbuf_reset(mb);
    pl_set_str(&cmd, "stat");
    restund_cmd(&cmd, mb);
    mbuf_write_u8(mb, 0);
    mbuf_set_pos(mb, 0);
    mbuf_read_str(mb, buf, sizeof(buf));
    memcpy(&oldreq, &rstats, sizeof(oldreq));
    sscanf(buf, 
           "binding_req %lu\n"
           "allocate_req %lu\n"
           "refresh_req %lu\n"
           "chanbind_req %lu\n"
           "unknown_req %lu\n",
           &rstats.n_bind_req,
           &rstats.n_alloc_req,
           &rstats.n_refresh_req,
           &rstats.n_chanbind_req,
           &rstats.n_unk_req);
    rstats.ts = now;


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

    // write out stuff
    mbuf_reset(mb);
    mbuf_write_str(mb, "[{\"name\": \"restund\","
                   "\"columns\": ["
                   "\"time\", \"host\", "
                   "\"utime\", \"stime\", "
                   "\"req_bind\", \"req_alloc\", \"req_refresh\", \"req_chanbind\", \"req_unk\", "
                   "\"allocs_cur\", \"bitrate_rx\", \"bitrate_tx\", \"bitrate_tot\""
                   "],");
    mbuf_printf(mb, "\"points\": [[%ld, \"%s\", %ld, %ld, %ld, %ld, %ld, %ld, %ld, %d, %ld, %ld, %ld]]", 
                now, stuff.identifier,
                cpustats.usr, cpustats.sys,
                rstats.n_bind_req - oldreq.n_bind_req,
                rstats.n_alloc_req - oldreq.n_alloc_req,
                rstats.n_refresh_req - oldreq.n_refresh_req,
                rstats.n_chanbind_req - oldreq.n_chanbind_req,
                rstats.n_unk_req - oldreq.n_unk_req,
                tstats.allocc_cur,
                8 * (tstats.bytec_rx - oldturn.bytec_rx)/ (tstats.ts - oldturn.ts),
                8 * (tstats.bytec_tx - oldturn.bytec_tx)/ (tstats.ts - oldturn.ts),
                8 * (tstats.bytec - oldturn.bytec)/ (tstats.ts - oldturn.ts));
    mbuf_write_str(mb, "}]");
    mbuf_set_pos(mb, 0);

    udp_send_anon(&stuff.dest_udp, mb);
    mb = mem_deref(mb);
}


static int module_init(void)
{
    struct pl addr;
    uint32_t port;
    int err = 0;

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
        restund_error("status: bad udp dest address: %r:%u",
                      &addr, port);
        goto out;
    }

    // initalize stats
    rstats.ts = time(NULL);
    rstats.n_bind_req = 0;
    rstats.n_alloc_req = 0;
    rstats.n_refresh_req = 0;
    rstats.n_chanbind_req = 0;
    rstats.n_unk_req = 0;

    tstats.ts = time(NULL);
    tstats.bytec_tx = 0;
    tstats.bytec_rx = 0;
    tstats.bytec = 0;
    tstats.allocc_tot = 0;
    tstats.allocc_cur = 0;

    /* start doing stuff */
    tmr_start(&stuff.tmr, stuff.freq * 1000, tic, NULL);

 out:
	return err;
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
