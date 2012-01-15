
#include <stdio.h>
#include <limits.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <lcmaps/lcmaps_log.h>

static const char * logstr = "static-mapping";

static char * match_column(const char* key, const char *buf) {
    const char *next_tab, *next_line;
    const char *next_col = strchr(buf, '\t');
    if (!next_col) {
        return NULL;
    }
    if (strncmp(buf, key, (next_col-buf)) != 0) {
        return NULL;
    }
    next_col++;
    size_t column_len;
    next_tab = strchr(next_col, '\t');
    next_line = strchr(next_col, '\n');
    if (!next_tab && !next_line) return NULL;
    if (!next_line || (next_tab < next_line)) {
        column_len = next_tab - next_col;
    } else {
        column_len = next_line - next_col;
    }
    char * result = (char *)malloc(column_len+1);
    result[column_len] = '\0';
    if (!result) return NULL;
    strncpy(result, next_col, column_len);
    return result;
}

#define buf_size 4096
static int get_proc_info_internal(int fd, uid_t *uid, gid_t *gid, pid_t *ppid) {
    int retval = 0;

    // Make sure we can ignore NULL variables.
    uid_t uid_int;
    gid_t gid_int;
    pid_t ppid_int;
    if (uid == NULL) {
        uid = &uid_int;
    }
    if (gid == NULL) {
        gid = &gid_int;
    }
    if (ppid == NULL) {
        ppid = &ppid_int;
    }

    *uid = -1;
    *gid = -1;
    *ppid = -1;
    const char *buf;
    char buffer[buf_size]; buffer[buf_size-1] = '\0';
    char * cuid, *cgid, *cppid;
    if (read(fd, buffer, buf_size-1) < 0) {
        retval = -errno;
        goto finalize;
    }
    buf = buffer;
    cuid = NULL;
    cgid = NULL;
    cppid = NULL;
    while (buf != NULL) {
        if (*ppid == -1) {
            cppid = match_column("PPid:", buf);
            if (cppid) {
                errno = 0;
                *ppid = strtol(cppid, NULL, 0);
                free(cppid);
                if (errno != 0) *ppid = -1;
            }
        } else if (*uid == -1) {
            cuid = match_column("Uid:", buf);
            if (cuid) {
                errno = 0;
                *uid = strtol(cuid, NULL, 0);
                free(cuid);
                if (errno != 0) *uid = -1;
            }
        } else if (*gid == -1) {
            cgid = match_column("Gid:", buf);
            if (cgid) { 
                errno = 0;
                *gid = strtol(cgid, NULL, 0);
                free(cgid);
                if (errno != 0) *gid = -1;
            }
            if (*gid != -1) {
                retval = 0;
                goto finalize;
            }
        } else {
            break;
        }
        buf = strchr(buf, '\n');
        if (buf != NULL) {
            buf++;
            if (*buf == '\0') break;
        }
    }
    retval = 1;

finalize:
    return retval;

}

int get_proc_info(pid_t pid, uid_t *uid, gid_t *gid, pid_t *ppid) {

    char path[PATH_MAX];
    if (snprintf(path, PATH_MAX-1, "/proc/%d/status", pid) >= PATH_MAX) {
        lcmaps_log(0, "%s: Error - overly long PID: %d\n", logstr, pid);
        return -1;
    }
    int fd;
    if ((fd = open(path, O_RDONLY)) == -1) {
        lcmaps_log(0, "%s: Error opening process %d status file: %d %s\n", logstr, pid, errno, strerror(errno));
        return -1;
    }
    int result;
    if ((result = get_proc_info_internal(fd, uid, gid, ppid))) {
        lcmaps_log(0, "%s: Error - unable to parse status file for PID %d: %d\n", logstr, pid, result);
        close(fd);
        return -1;
    }
    close(fd);

    return 0;
}

