#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>

#define PATH_LEN               128
#define MAX_LOG_LINE_LEN       256
#define CMD_BUF_SIZE           256
#define ALARM_PERIOD           1800 // 0.5 hour

#define _SYSLOG_DEBUG

#ifdef  _SYSLOG_DEBUG
#define LOG_MODULE             "=configd"
#else
#define PRIV_LOG_FILE          "/tmp/configd.log"
#endif

#define FINAL_BOOT_CHECK_FILE  "/tmp/zfinal"

static volatile unsigned char g_syncflag = 0;
static volatile unsigned char g_alarmflag = 0;

static void _log(int level, const char *format, ...)
{
	char buf[MAX_LOG_LINE_LEN+1];

    if (level < 0 || level > 7) {
        level = 5; // LOG_NOTICE
    }

	va_list ptr;
	va_start(ptr, format);
	vsnprintf(buf, MAX_LOG_LINE_LEN, format, ptr);
	va_end(ptr);

#ifdef _SYSLOG_DEBUG
	openlog(LOG_MODULE, 0, LOG_USER);
	syslog(level, "%s", buf);
	closelog();
#else
    FILE *fp;
    if ((fp = fopen(PRIV_LOG_FILE, "a+")) == NULL) {
		perror("fopen - Can't open log file");
		exit(1);
	}
	fprintf(fp, "%s\n", buf);
    fclose(fp);

    struct stat sbuf;

    if (stat(PRIV_LOG_FILE, &sbuf) == 0) {
        // larger than 100k, del it
        if (sbuf.st_size > 102400) {
            remove(PRIV_LOG_FILE);
        }
    }
#endif
}

static void alarm_enable(unsigned char flag)
{
    if (flag) {
        _log(LOG_DEBUG, "alarm start");
        alarm(0);
        alarm(ALARM_PERIOD);
    } else {
        _log(LOG_DEBUG, "alarm stop");
        alarm(0);
    }
}

static void sig_handler(int sig)
{
    switch (sig) {
    case SIGUSR1:
        // recived USR1 from cluster
        g_syncflag = 1;
        _log(LOG_DEBUG, "received USR1 signal");
        break;

    case SIGALRM:
        // periodically sync for keeping public configs same
        g_alarmflag = 1;
        _log(LOG_DEBUG, "alarm time reached");
        break;
    }
}

static int check_cmd_response(const char *cmd, char *ret, unsigned int ret_size)
{
    if (cmd == NULL || ret_size == 0 || ret == NULL) {
        _log(LOG_INFO, "%s invalid parameters", __func__);
        return -1;
    }

    FILE *fd = popen(cmd, "r");
    if (fd == NULL) {
        _log(LOG_INFO, "popen err");
        return -1;
    }

    // reads in at most one less than size characters from stream
    // and stores them into the buffer pointed to by s.
    // Reading stops after an EOF or a newline.
    fgets(ret, ret_size, fd);
    pclose(fd);

    int rlen = 0;
    rlen = strlen(ret);

    if (rlen > 0 && ret[rlen-1] == '\n') {
        ret[rlen-1] = '\0';
    }

    return 0;
}

static int response_cluster(const char *inbuf)
{
    if (inbuf == NULL) {
        _log(LOG_INFO, "%s invalid parameter!", __func__);
        return -1;
    }

    const char * syncstr = "done"; // cfgsync will output done if success

    _log(LOG_DEBUG, "cluster sync [%s]", inbuf);

    if (strlen(inbuf) == strlen(syncstr) && strcmp(inbuf, syncstr) == 0) {
        // cfgsync ok, send USR1 to cluster
        _log(LOG_DEBUG, "send USR1 to cluster_mgt");

        if (system("kill -USR1 `pgrep /sbin/cluster_mgt`") < 0) {
            _log(LOG_INFO, "send USR1 error!");
            return -1;
        }
    } else {
        // cfgsync err, send USR2 to cluster
        _log(LOG_DEBUG, "send USR2 to cluster_mgt");

        if (system("kill -USR2 `pgrep /sbin/cluster_mgt`") < 0) {
            _log(LOG_INFO, "send USR2 error!");
            return -1;
        }
    }

    return 0;
}

static void cluster_sync_work(void)
{
    char cmd[CMD_BUF_SIZE+1];
    char cmd_res_buf[CMD_BUF_SIZE+1];
    int ret;

    // do sync & reload job
    snprintf(cmd, CMD_BUF_SIZE, "/usr/bin/cfgsync");
    memset(cmd_res_buf, 0, sizeof(cmd_res_buf));
    ret = check_cmd_response(cmd, cmd_res_buf, CMD_BUF_SIZE);
    if (ret < 0) {
        _log(LOG_INFO, "[cluster] check cmd response err!");
        return;
    }

    if (response_cluster(cmd_res_buf) < 0) {
        _log(LOG_INFO, "response cluster err!");
        return;
    }
}

static void alarm_sync_work(void)
{
    char cmd[CMD_BUF_SIZE+1];
    char cmd_res_buf[CMD_BUF_SIZE+1];
    int ret;

    // do sync & reload job
    snprintf(cmd, CMD_BUF_SIZE, "/usr/bin/cfgsync");
    memset(cmd_res_buf, 0, sizeof(cmd_res_buf));
    ret = check_cmd_response(cmd, cmd_res_buf, CMD_BUF_SIZE);
    if (ret < 0) {
        _log(LOG_INFO, "[alarm] check cmd response err!");
        return;
    }

    _log(LOG_DEBUG, "alarm sync [%s]", cmd_res_buf);
}

static void alarm_sync_work_portal(void)
{
    char cmd[CMD_BUF_SIZE+1];
    char cmd_res_buf[CMD_BUF_SIZE+1];
    int ret;

    // do sync & reload job
    snprintf(cmd, CMD_BUF_SIZE, "/usr/bin/portalsync");
    memset(cmd_res_buf, 0, sizeof(cmd_res_buf));
    ret = check_cmd_response(cmd, cmd_res_buf, CMD_BUF_SIZE);
    if (ret < 0) {
        _log(LOG_INFO, "[alarm] check portalsync response err!");
        return;
    }
}

static int configd_init(void)
{
    g_alarmflag = 0;
    g_syncflag = 0;

    // register USR1 signal handler
    if (signal(SIGUSR1, sig_handler) == SIG_ERR) {
        _log(LOG_INFO, "signal USR1 err");
        return -1;
    }

    // register ALARM signal handler
    if (signal(SIGALRM, sig_handler) == SIG_ERR) {
        _log(LOG_INFO, "signal ALRM err");
        return -1;
    }

    // make sure all boot scripts have been booted
    while (1) {
        if (access(FINAL_BOOT_CHECK_FILE, F_OK) != 0) {
            sleep(3);
            continue;
        }

        break;
    }
    _log(LOG_DEBUG, "all boot scripts have been booted");

    alarm_enable(1);

    return 0;
}

static void check_sync()
{
    if (g_alarmflag) {
        g_alarmflag = 0;

        alarm_enable(0);
        alarm_sync_work();
        alarm_sync_work_portal();
        alarm_enable(1);
    }

    if (g_syncflag) {
        g_syncflag = 0;

        alarm_enable(0);
        cluster_sync_work();
        alarm_enable(1);
    }
}

int main(int argc, char *argv[])
{
    _log(LOG_DEBUG, "configd start...");

    if (configd_init() < 0) {
        return -1;
    }

    while (1) {
        check_sync();
        sleep(5);
    }

    return 0;
}
