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
    long unsigned int start;
    long unsigned int stop;
    long unsigned int utime_start;
    long unsigned int utime_stop;
    long unsigned int stime_start;
    long unsigned int stime_stop;
} stuff;


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

static void stats_handler(struct mbuf *mb)
{
    long unsigned dt, user, sys;

    cpumon(&stuff.utime_stop, &stuff.stime_stop, &stuff.stop);

    dt = stuff.stop - stuff.start;
    user = 100 * (stuff.utime_stop - stuff.utime_start) / dt;
    sys = 100 * (stuff.stime_stop - stuff.stime_start) / dt;

    stuff.utime_start = stuff.utime_stop;
    stuff.stime_start = stuff.stime_stop;
    stuff.start = stuff.stop;
    (void)mbuf_printf(mb, "usr %lu\n", user);
    (void)mbuf_printf(mb, "sys %lu\n", sys);
}


static struct restund_cmdsub cmd_cpu = {
	.cmdh = stats_handler,
	.cmd  = "cpuusage",
};


static int module_init(void)
{
	restund_debug("cpu usage: module loaded\n");
	restund_cmd_subscribe(&cmd_cpu);

    cpumon(&stuff.utime_start, &stuff.stime_start, &stuff.start);
	return 0;
}


static int module_close(void)
{
	restund_debug("cpu usage: module closed\n");
	restund_cmd_unsubscribe(&cmd_cpu);
	return 0;
}


const struct mod_export exports = {
	.name  = "cpu usage",
	.type  = "stun",
	.init  = module_init,
	.close = module_close
};
