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

	struct sa dest_udp;

    long unsigned int start;
    long unsigned int stop;
    long unsigned int utime_start;
    long unsigned int utime_stop;
    long unsigned int stime_start;
    long unsigned int stime_stop;
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


static void read_pid(long unsigned int *utime, long unsigned int *stime) {
    char buf[512];
    FILE *fp;
    sprintf(buf, "/proc/%d/stat", getpid());
    fp = fopen(buf, "r");
    if (0 != fp) {
        fgets(buf, sizeof(buf), fp); 
        // see man proc
        sscanf(buf, 
               "%*d %*s %*c %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %lu %lu %*s",
               utime, stime);
        fclose(fp);
    }
}


static void read_stat(long unsigned int *time_total) {
    char buf[512];
    int vals[10];
    FILE *fp;
    fp = fopen("/proc/stat", "r");
    if (0 != fp) {
        long unsigned int sum = 0;
        int i;
        fgets(buf, sizeof(buf), fp); 
        sscanf(buf, "cpu\t%d %d %d %d %d %d %d", 
               &vals[0], &vals[1], &vals[2], &vals[3], 
               &vals[4], &vals[5], &vals[6]);
        for (i = 0; i < 7; i++) {
            sum += vals[i];
        }
        *time_total = sum;
        fclose(fp);
    }
}


static void cpumon(long unsigned int *utime, long unsigned int *stime,
                   long unsigned int *total) {
    read_pid(utime, stime);
    read_stat(total);
}


static void tic(void *arg) {
    double dt, user, sys;
	const time_t now = time(NULL);
    int err;

    struct mbuf *mb;
    struct mbuf *cmdbuf;
	struct pl cmd;
    char buf[4096];
    struct turnstats oldturn;

    cpumon(&stuff.utime_stop, &stuff.stime_stop, &stuff.stop);

    dt = stuff.stop - stuff.start;
    user = 100.0 * (stuff.utime_stop - stuff.utime_start) / dt;
    sys = 100.0 * (stuff.stime_stop - stuff.stime_start) / dt;
    stuff.utime_start = stuff.utime_stop;
    stuff.stime_start = stuff.stime_stop;
    stuff.start = stuff.stop;
    // tmr_start(struct tmr *tmr, uint64_t delay, tmr_h *th, void *arg);
	tmr_start(&stuff.tmr, 15 * 1000, tic, NULL);
    restund_debug("influxdb tic usr %f sys %f delta %f\n", user, sys, dt);

    mb = mbuf_alloc(4096);
    cmdbuf = mbuf_alloc(1024);

    mbuf_write_str(mb, "[{\"name\": \"restund\","
                   "\"columns\": [\"time\", \"utime\", \"stime\"],");

    // get turn stats
    pl_set_str(&cmd, "turnstats");
	restund_cmd(&cmd, cmdbuf);
    mbuf_write_u8(cmdbuf, 0);
    mbuf_set_pos(cmdbuf, 0);
    mbuf_read_str(cmdbuf, buf, sizeof(buf));
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

    restund_debug("turnstats bytec %d %d in %d, %f\n", tstats.bytec, oldturn.bytec, tstats.ts - oldturn.ts,
                  (tstats.bytec - oldturn.bytec)/(tstats.ts - oldturn.ts));



    mbuf_printf(mb, "\"points\": [%ld, %f, %f]", 
                now, user, sys);
    mbuf_write_str(mb, "}]");
    mbuf_set_pos(mb, 0);

    err = udp_send_anon(&stuff.dest_udp, mb);


	mb = mem_deref(mb);
	cmdbuf = mem_deref(cmdbuf);
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
    cpumon(&stuff.utime_start, &stuff.stime_start, &stuff.start);
	tmr_start(&stuff.tmr, 15 * 1000, tic, NULL);

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
