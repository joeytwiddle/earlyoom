/* Kill the most memory-hungy process */

#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <limits.h>                     // for PATH_MAX
#include <unistd.h>
#include <regex.h>
#include <math.h>

#include "kill.h"

#define MAX_BUFFER_SIZE 4000

extern int enable_debug;
extern regex_t excluded_cmdlines_regexp;
extern regex_t preferred_cmdlines_regexp;

struct procinfo {
	int oom_score;
	int oom_score_adj;
	unsigned long vm_rss;
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

const char * const fopen_msg = "fopen %s failed: %s\n";

/* Read /proc/pid/{oom_score, oom_score_adj, statm}
 * Caller must ensure that we are already in the /proc/ directory
 */
static struct procinfo get_process_stats(int pid)
{
	char buf[MAX_BUFFER_SIZE];
	FILE * f;
	struct procinfo p = {0, 0, 0, 0};

	// Read /proc/[pid]/oom_score
	snprintf(buf, sizeof(buf), "%d/oom_score", pid);
	f = fopen(buf, "r");
	if(f == NULL) {
		printf(fopen_msg, buf, strerror(errno));
		p.exited = 1;
		return p;
	}
	fscanf(f, "%d", &(p.oom_score));
	fclose(f);

	// Read /proc/[pid]/oom_score_adj
	snprintf(buf, sizeof(buf), "%d/oom_score_adj", pid);
	f = fopen(buf, "r");
	if(f == NULL) {
		printf(fopen_msg, buf, strerror(errno));
		p.exited = 1;
		return p;
	}
	fscanf(f, "%d", &(p.oom_score_adj));
	fclose(f);

	// Read VmRss from /proc/[pid]/statm
	snprintf(buf, sizeof(buf), "%d/statm", pid);
	f = fopen(buf, "r");
	if(f == NULL)
	{
		printf(fopen_msg, buf, strerror(errno));
		p.exited = 1;
		return p;
	}
	fscanf(f, "%*u %lu", &(p.vm_rss));
	fclose(f);

	return p;
}

static int get_process_mem_stats(int pid, long *VmSize, long *VmRSS)
{
	char buf[PATH_MAX];

	snprintf(buf, sizeof(buf), "%d/statm", pid);

	FILE * statm = fopen(buf, "r");
	if(statm == 0)
	{
		// Process may have died in the meantime
		return 0;
	}

	if(fscanf(statm, "%lu %lu", VmSize, VmRSS) < 2)
	{
		fprintf(stderr, "Error: Could not parse %s\n", buf);
		fclose(statm);
		return 0;
	}
	fclose(statm);

	return 1;
}

/* More things we could read:
 *
 * /proc/[pid]/fd will link to each file the process has open.  Checking which of these files was recently written or accessed, might help us decide which processes are active and which are idle.
 *
 * We could look at /proc/[pid]/fdinfo to check the open status in 'flags' and even monitor the position in the file ('pos') for changes.
 *
 *
 *
 */

/*
 * Find the process with the largest oom_score and kill it.
 * See trigger_kernel_oom() for the reason why this is done in userspace.
 */
static void userspace_kill(DIR *procdir, int sig, int ignore_oom_score_adj)
{
	struct dirent * d;
	char buf[MAX_BUFFER_SIZE];
	int pid;
	int victim_pid = 0;
	int victim_badness = 0;
	unsigned long victim_vm_rss = 0;
	char name[PATH_MAX];
	char cmdline[MAX_BUFFER_SIZE];
	struct procinfo p;
	int badness;
	long long unsigned int uptime;
	long long unsigned int proc_start_time;
	long VmSize, VmRSS;

	// TODO: Probably more efficient to get uptime from sysinfo().  http://stackoverflow.com/questions/1540627/what-api-do-i-call-to-get-the-system-uptime#1544090
	FILE * proc_uptime_file = fopen("/proc/uptime", "r");
	fscanf(proc_uptime_file, "%llu", &uptime);
	fclose(proc_uptime_file);

	rewinddir(procdir);
	while(1)
	{
		errno = 0;
		d = readdir(procdir);
		if(d == NULL)
		{
			if(errno != 0)
				perror("readdir returned error");

			break;
		}

		// proc contains lots of directories not related to processes,
		// skip them
		if(!isnumeric(d->d_name))
			continue;

		pid = strtoul(d->d_name, NULL, 10);

		if(pid == 1)
			// Let's not kill init.
			continue;

		p = get_process_stats(pid);

		if(p.exited == 1)
			// Process may have died in the meantime
			continue;

		badness = p.oom_score;
		if(ignore_oom_score_adj && p.oom_score_adj > 0)
			badness -= p.oom_score_adj;

		float thru = 0;
		//if(badness > victim_badness || enable_debug)
		// The above heuristic does not apply now we might increase the badness (preferred_cmdlines_regexp and mem_modifier)
		// The badness given to us by the system is too dependent on memory usage, so it isn't very useful to us, since we care more about age!
		// The system badness *does* contain useful info about though (e.g. if the process marked itself as bad), but we are handling that ourselves via preferred_cmdlines_regexp.
		//badness = badness / 4;
		// However this approach is undesirable in the case where no processes are "preferred".  In such situations, we do care about self-marked processes, and less about process age.
		// Ideally I just want to discount memory usage from the system oom_score.
		// So we reduce the system p.oom_score but keep p.oom_score_adj (the process's self-marked badness).
		// To do that we must first discount oom_score_adj from the system oom_score, then restore it afterwards.
		badness = (p.oom_score - p.oom_score_adj) / 8 + p.oom_score_adj;
		if (1)
		{
			int time_modifier = 0;
			snprintf(buf, sizeof(buf), "%d/stat", pid);
			FILE * stat = fopen(buf, "r");
			long int priority;
			fscanf(stat, "%*d (%[^)]) %*s %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %ld %*d %*d %*d %llu", name, &priority, &proc_start_time);
			fclose(stat);
			proc_start_time /= sysconf(_SC_CLK_TCK);
			long long unsigned int time_running = uptime - proc_start_time;
			thru = time_running / (float)(60 * 60 * 8);
			if (thru > 1) {
				thru = 1;
			}
			if (thru < 0) {
				thru = 0;
			}
			// No longer used:
			// Curved (exponential?)
			//time_modifier = 300 - 300.0 / (1.0 + 299 * thru);
			// Linear
			//time_modifier = 300 * thru;
			// Curved (exponential)
			time_modifier = 400 * pow(thru, 1.25);
			// TODO: Instead of the above, I am tempted to multiply (positive) cmdline_modifier and mem_modifier by thru.  Maybe original (positive) badness too?  In that case, just multiply the final result, if it is positive.
			// Make thru curved!
			//thru = 1.0 - 1.0 / (1.0 + 60.0 * thru);

			if (!get_process_mem_stats(pid, &VmSize, &VmRSS))
			{
				continue;
			}
			// VmRSS: RAM currently consumed by process
			//int mem_modifier = VmRSS / 1024;
			// VmSize: Total memory consumed by process, including RAM, swapped memory, and shared memory (e.g. executable instructions cached on FS, or shared with other processes)
			// I reduced the score because I didn't find it very helpful.
			//int mem_modifier = VmSize / 1024 / 4 / 2;
			// In fact I find it unhelpful!
			int mem_modifier = 0;

			int cmdline_modifier = 0;
			snprintf(buf, PATH_MAX, "%d/cmdline", pid);
			int len = read_contents_of_file(buf, cmdline, sizeof(cmdline) - 1);
			convert_nulls_to_spaces(cmdline, len);
			// Remove the usual trailing space
			if (cmdline[len-1] == ' ')
			{
				cmdline[len-1] = 0;
			}

			if (regexec(&excluded_cmdlines_regexp, cmdline, (size_t)0, NULL, 0) == 0)
			{
				//fprintf(stderr, "Process %i is EXCLUDED!\n", pid, name);
				cmdline_modifier -= 400;
			}
			if (regexec(&preferred_cmdlines_regexp, cmdline, (size_t)0, NULL, 0) == 0)
			{
				//fprintf(stderr, "Process %i is PREFERRED!\n", pid, name);
				cmdline_modifier += 400;
			} else {
				// We will only apply the time_modifier to favored processes
				time_modifier = 0;
			}

			// Now the we have checked the cmdline, we make it more appropriate for logging.
			if (len > 160)
			{
				cmdline[160] = '\0';
			}
			// Many processes have an empty cmdline.  So we will display the process name instead.  (Which is usually surrounded by parenthesese.)
			if (strlen(cmdline) == 0)
			{
				strcpy(cmdline, name);
			}

			int modifier = time_modifier + mem_modifier + cmdline_modifier;
			if((enable_debug && modifier != 0) || sig == 0)
				fprintf(stderr, "[%5u] time_running: %4llum (%0.2f) priority: %3ld badness: %3d + %3d + %3d + %3d = %3d cmdline=\"%s\"\n", pid, time_running/60, thru, priority, badness, time_modifier, mem_modifier, cmdline_modifier, badness + modifier, cmdline);
				//fprintf(stderr, "[%5u] time_running: %4llum (%0.2f) priority: %3ld badness: %3d + 0*%3d + %3f*(%3d + %3d) = %3d cmdline=\"%s\"\n", pid, time_running/60, thru, priority, badness, time_modifier, thru, mem_modifier, cmdline_modifier, badness + modifier, cmdline);
			badness = badness + modifier;
		}

		if(enable_debug)
			printf("pid %5d: badness %3d vm_rss %6lu\n", pid, badness, p.vm_rss);

		if(badness > victim_badness)
		{
			victim_pid = pid;
			victim_badness = badness;
			victim_vm_rss = p.vm_rss;
			if(enable_debug)
				printf("    ^ new victim (higher badness)\n");
		} else if(badness == victim_badness && p.vm_rss > victim_vm_rss) {
			victim_pid = pid;
			victim_vm_rss = p.vm_rss;
			if(enable_debug)
				printf("    ^ new victim (higher vm_rss)\n");
		}
	}

	if(victim_pid == 0)
	{
		fprintf(stderr, "Error: Could not find a process to kill. Sleeping 10 seconds.\n");
		sleep(10);
		return;
	}

	name[0]=0;
	snprintf(buf, sizeof(buf), "%d/stat", victim_pid);
	FILE * stat = fopen(buf, "r");
	//fscanf(stat, "%*d %s", name);
	fscanf(stat, "%*d (%[^)]) %*s %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %llu", name, &proc_start_time);
	proc_start_time /= sysconf(_SC_CLK_TCK);
	long long unsigned int time_running = uptime - proc_start_time;
	fclose(stat);

	if(sig != 0)
		fprintf(stderr, "Killing process %d %s with badness %d time_running=%0.1fm mem=%ld/%ldMB\n", victim_pid, name, victim_badness, time_running/60.0, VmRSS, VmSize);

	if(kill(victim_pid, sig) != 0)
	{
		perror("Could not kill process");
		// Killing the process may have failed because we are not running as root.
		// In that case, trying again in 100ms will just yield the same error.
		// Throttle ourselves to not spam the log.
		fprintf(stderr, "Sleeping 10 seconds\n");
		sleep(10);
	}
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
 * Because of these issues, kill_by_rss() is used instead by default.
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
