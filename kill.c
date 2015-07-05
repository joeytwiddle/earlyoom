/* Kill the most memory-hungy process */

#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <limits.h>                     // for PATH_MAX

#include "kill.h"

extern int enable_debug;

struct procinfo {
	int oom_score;
	int oom_score_adj;
	int exited;
};

static int isnumeric(char* str)
{
	int i=0;

	// Empty string is not numeric
	if(str[0]==0)
		return 0;

	while(1)
	{
		if(str[i]==0) // End of string
			return 1;

		if(isdigit(str[i])==0)
			return 0;

		i++;
	}
}

/* Read /proc/pid/{oom_score, oom_score_adj, statm}
 * Caller must ensure that we are already in the /proc/ directory
 */
static struct procinfo get_process_stats(int pid)
{
	char buf[256];
	FILE * f;
	struct procinfo p = {0, 0, 0};

	snprintf(buf, sizeof(buf), "%d/oom_score", pid);
	f = fopen(buf, "r");
	if(f == NULL) {
		p.exited = 1;
		return p;
	}
	fscanf(f, "%d", &(p.oom_score));
	fclose(f);

	snprintf(buf, sizeof(buf), "%d/oom_score_adj", pid);
	f = fopen(buf, "r");
	if(f == NULL) {
		p.exited = 1;
		return p;
	}
	fscanf(f, "%d", &(p.oom_score_adj));
	fclose(f);

	return p;
}

long read_contents_of_file(char *filename, char *file_contents_buffer, long max_len)
{
	long input_file_size = 0;
	FILE *input_file = fopen(filename, "rb");
	char c;
	while ( (c = fgetc(input_file)) != EOF )
	{
		file_contents_buffer[input_file_size] = c;
		input_file_size++;
		if (input_file_size == max_len) {
			break;
		}
	}
	fclose(input_file);
	file_contents_buffer[input_file_size] = 0;
	return input_file_size;
}

void convert_nulls_to_spaces(char *str, int len)
{
	int i;
	for (i=0; i<len; i++) {
		if (str[i] == 0) {
			str[i] = 32;
		}
	}
}

/*
 * Find the process with the largest oom_score and kill it.
 * See trigger_kernel_oom() for the reason why this is done in userspace.
 */
static void userspace_kill(DIR *procdir, int sig, int ignore_oom_score_adj)
{
	struct dirent * d;
	char buf[256];
	int pid;
	int victim_pid = 0;
	int victim_points = 0;
	char name[PATH_MAX];
	struct procinfo p;
	int badness;
	#define CMDLINE_MAX 250
	char cmdline[CMDLINE_MAX];
	int len;

	rewinddir(procdir);
	while(1)
	{
		d = readdir(procdir);
		if(d == NULL)
			break;

		if(!isnumeric(d->d_name))
			continue;

		pid = strtoul(d->d_name, NULL, 10);

		p = get_process_stats(pid);

		if(p.exited == 1)
			// Process may have died in the meantime
			continue;

		badness = p.oom_score;
		if(ignore_oom_score_adj && p.oom_score_adj > 0)
			badness -= p.oom_score_adj;

		if(enable_debug)
			printf("pid %5d: badness %3d\n", pid, badness);

		// We don't need to check this, but it is a good optimization, reducing the number of files that will be read.
		if(badness > victim_points)
		{
			// If the process is marked as excluded, then reduce its score.
			snprintf(buf, PATH_MAX, "%d/cmdline", pid);
			len = read_contents_of_file(buf, cmdline, CMDLINE_MAX-1);
			convert_nulls_to_spaces(cmdline, len);
			if (regexec(&excluded_cmdlines_regexp, cmdline, (size_t)0, NULL, 0) == 0)
			{
				//fprintf(stderr, "Process is EXCLUDED!  %i %s\n", pid, cmdline);
				badness /= 32;
			}
		}

		if(badness > victim_points)
		{
			victim_pid = pid;
			victim_points = badness;
			if(enable_debug)
				printf("    ^ new victim\n");
		}
	}

	if(victim_pid == 0)
	{
		fprintf(stderr, "Error: Could not find a process to kill\n");
		exit(9);
	}

	if (!enable_debug)
	{
		name[0]=0;
		snprintf(buf, sizeof(buf), "%d/stat", victim_pid);
		FILE * stat = fopen(buf, "r");
		fscanf(stat, "%*d %s", name);
		fclose(stat);
	} else {
		// In debug mode, instead of the process name, we display the whole cmdline (i.e. the name and the arguments passed).
		snprintf(buf, PATH_MAX, "%d/cmdline", victim_pid);
		len = read_contents_of_file(buf, name, PATH_MAX-1);
		convert_nulls_to_spaces(name, len);
	}

	if(sig != 0)
		fprintf(stderr, "Killing process %d %s\n", victim_pid, name);

	if(kill(victim_pid, sig) != 0)
		perror("Could not kill process");
}

/*
 * Invoke the kernel oom killer by writing "f" into /proc/sysrq-trigger
 *
 * This approach has a few problems:
 * 1) It is disallowed by default (even for root) on Fedora 20.
 *    You have to first write "1" into /proc/sys/kernel/sysrq to enable the "f"
 *    trigger.
 * 2) The Chrome web browser assigns a penalty of 300 onto its own tab renderer
 *    processes. On an 8GB RAM machine, this means 2400MB, and will lead to every
 *    tab being killed before the actual memory hog
 *    See https://code.google.com/p/chromium/issues/detail?id=333617 for more info
 * 3) It is broken in 4.0.5 - see
 *    https://github.com/rfjakob/earlyoom/commit/f7e2cedce8e9605c688d0c6d7dc26b7e81817f02
 * Because of these issues, userspace_kill() is used instead by default.
 */
void trigger_kernel_oom(int sig)
{
	FILE * trig_fd;
	trig_fd = fopen("sysrq-trigger", "w");
	if(trig_fd == NULL)
	{
		perror("Cannot open /proc/sysrq-trigger");
		exit(7);
	}
	if(sig == 9)
	{
		fprintf(stderr, "Invoking oom killer: ");
		if(fprintf(trig_fd, "f\n") != 2)
			perror("failed");
		else
			fprintf(stderr, "done\n");
	}
	fclose(trig_fd);
}

void handle_oom(DIR * procdir, int sig, int kernel_oom_killer, int ignore_oom_score_adj)
{
	if(kernel_oom_killer)
		trigger_kernel_oom(sig);
	else
		userspace_kill(procdir, sig, ignore_oom_score_adj);
}
