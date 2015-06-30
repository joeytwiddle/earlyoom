/* If the available memory goes below this percentage, we start killing
 * processes. 10 is a good start. */

/* My machine with 2gig RAM and 2gig swap started grinding when swap fell below 300Mb.  (Memory would usually be close to 300Mb at this time, but sometimes a bit over. */
//#define MIN_AVAIL_PERCENT 15
/* But on my machine with 8gig RAM and 0gig swap, I think the threshold should be around 300 or 400Mb. */
#define MIN_AVAIL_PERCENT 5
/* Or perhaps we should just set a fixed amount, if it is generally true that Linux machines only get laggy when they have <300MB RAM (or <300MB of swap when swap is present. */
/* Is memory more valuable than swap?  If I have 100 swap but 400 RAM then I might be ok, but if I have 100 RAM and 400 swap, then I'm in trouble!  Although in my experience, Linux will even them out fairly soon, so it seems reasonable to threshold the total free. */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fts.h>
#include <err.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
#include <regex.h>

#include "sysinfo.h"

// The excluded regexp allows us to mark some processes as too precious to kill.
// For example, closing the core google-chrome process will close all the tabs, when there are likely just a few tabs that can be killed to relclaim a lot of memory.  So we use the regexp to match just the browser process (no args = "$"), but not the tab processes (tend to have args "--type=renderer").
// DONE: Perhaps "never kill" is not the best rule for this case.  We could instead divide the score of matching processes by 32, so they are less likely to be killed prematurely, but will ultimately be considered if needed.
// CONSIDER: We could opt for a different approach in this case.  We could increase the score of specific processes, e.g. "chrome --type=renderer" so that they will be more likely to be reclaimed.  Although the multiplier may need to be over 5 for a large chrome tab to beat the firefox process.  Perhaps firefox and chrome base processes could be given reduced score because we expect them to be large but they are important.  (OTOH, they tend to recover reasonably from being killed, perhaps better than other apps.)
// NOTE: solutions based on process name will never be ideal: a malicious process could rename itself to evade consideration.  Ideas for alternative approaches would be welcomed!  (The kernel-space oom killer's exclusions requires PIDs be specified, which is powerful and accurate, but not very easy to use.)
// TODO: Slightly reduce score for recent processes.  (Is this stored somewhere in /proc/<pid>/...?)  Because I found recently that earlyoom killed the google-chrome tabset that I was working on, when it probably would have been better to close some older tabsets.

// I want to match all init, sshd and firefox processes, but ONLY the initial chrome process.  Chrome tab processes and extension processes will be treated normally.
char *excluded_cmdlines_pattern = "(^|/)(((init|X|sshd|firefox)( .*|$))|chrome|chromium-browser)$";
regex_t excluded_cmdlines_regexp;

/* "free -/+ buffers/cache"
 * Memory that is actually available to applications */
static unsigned long get_kb_avail(void)
{
	meminfo();
	return kb_main_free + kb_main_buffers + kb_main_cached;
}

static unsigned long get_kb_swap_avail(void)
{
	// Assumes meminfo() was called recently!
	// Please please uncomment this if you decide to *only* use the swap reading.
	//meminfo();
	return kb_swap_free /* + kb_swap_cached */;
}

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

#ifndef USE_KERNEL_OOM_KILLER
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
 * Find the process with the largest RSS and kill it.
 * See trigger_oom_killer() for the reason why this is done in userspace.
 */
static void kill_by_rss(DIR *procdir, int sig)
{
	struct dirent * d;
	char buf[PATH_MAX];
	int pid;
	int hog_pid=0;
	unsigned long hog_rss=0;
	char name[PATH_MAX];
	#define CMDLINE_MAX 250
	char cmdline[CMDLINE_MAX];
	int len;

	rewinddir(procdir);
	while(1)
	{
		d=readdir(procdir);
		if(d==NULL)
			break;

		if(!isnumeric(d->d_name))
			continue;

		pid=strtoul(d->d_name, NULL, 10);

		snprintf(buf, PATH_MAX, "%d/statm", pid);

		FILE * statm = fopen(buf, "r");
		if(statm == 0)
		{
			// Process may have died in the meantime
			//fprintf(stderr, "Info: Could not open /proc/%s: %s\n", buf, strerror(errno));
			continue;
		}

		long VmSize=0, VmRSS=0;
		if(fscanf(statm, "%lu %lu", &VmSize, &VmRSS) < 2)
		{
			fprintf(stderr, "Error: Could not parse %s\n", buf);
			exit(8);
		}
		fclose(statm);

		// We don't need to check this, but it is a good optimization, reducing the number of files that will be read.
		if(VmRSS > hog_rss)
		{
			// If the process is marked as excluded, then reduce its score.
			snprintf(buf, PATH_MAX, "%d/cmdline", pid);
			len = read_contents_of_file(buf, cmdline, CMDLINE_MAX-1);
			convert_nulls_to_spaces(cmdline, len);
			if (regexec(&excluded_cmdlines_regexp, cmdline, (size_t)0, NULL, 0) == 0)
			{
				//fprintf(stderr, "Process is EXCLUDED!  %i %s\n", pid, cmdline);
				VmRSS /= 32;
			}
		}

		if(VmRSS > hog_rss)
		{
			hog_pid=pid;
			hog_rss=VmRSS;
		}
	}

	if(hog_pid==0)
	{
		fprintf(stderr, "Error: Could not find a process to kill\n");
		exit(9);
	}

	/*
	name[0]=0;
	snprintf(buf, PATH_MAX, "%d/stat", hog_pid);
	FILE * stat = fopen(buf, "r");
	fscanf(stat, "%d %s", &pid, name);
	fclose(stat);
	*/
	snprintf(buf, PATH_MAX, "%d/cmdline", hog_pid);
	len = read_contents_of_file(buf, name, PATH_MAX-1);
	convert_nulls_to_spaces(name, len);

	if(sig!=0)
		fprintf(stderr, "Killing process %d %s\n", hog_pid, name);

	if(kill(hog_pid, sig) != 0)
	{
		fprintf(stderr, "Warning: Could not kill process: %s\n", strerror(errno));
	}

	#undef CMDLINE_MAX
}
#else
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
 * Because of these issues, kill_by_rss() is used instead by default.
 */
void trigger_oom_killer(int sig)
{
	int trig_fd;
	trig_fd = open("sysrq-trigger", O_WRONLY);
	if(trig_fd == -1)
	{
		fprintf(stderr, "Warning: Cannot open /proc/sysrq-trigger: %s. ");
		return;
	}
	if(sig!=9)
		return;
	fprintf(stderr, "Invoking oom killer: ");
	if(write(trig_fd, "f", 1) == -1)
		fprintf("%s\n", strerror(errno));
	else
		fprintf(stderr, "done\n");
}
#endif


void handle_oom(DIR * procdir, int sig)
{
#ifndef USE_KERNEL_OOM_KILLER
	kill_by_rss(procdir, sig);
#else
	trigger_oom_killer(sig);
#endif
}

int main(int argc, char *argv[])
{
	unsigned long kb_avail, kb_min, kb_swap_avail, oom_cnt=0;

	time_t rawtime;
	struct tm * timeinfo;
	char time_str[256];
	#define GET_FORMATTED_TIME time(&rawtime); timeinfo = localtime(&rawtime); strftime(time_str, sizeof(time_str), "%B %e %H:%m:%S", timeinfo);

	if (regcomp(&excluded_cmdlines_regexp, excluded_cmdlines_pattern, REG_EXTENDED|REG_NOSUB) != 0)
	{
		fprintf(stderr, "Could not compile regexp: %s\n", excluded_cmdlines_pattern);
		exit(6);
	}
	// regfree(&excluded_cmdlines_regexp);

	/* To be able to observe in real time what is happening when the
	 * output is redirected we have to explicitely request line
	 * buffering */
	setvbuf(stdout , NULL , _IOLBF , 80);

	fprintf(stderr, "earlyoom %s\n", GITVERSION);

	if(chdir("/proc")!=0)
	{
		fprintf(stderr, "Error: Could not cd to /proc: %s\n", strerror(errno));
		exit(4);
	}

	DIR *procdir = opendir(".");
	if(procdir==NULL)
	{
		fprintf(stderr, "Error: Could not open /proc: %s\n", strerror(errno));
		exit(5);
	}

	kb_avail = get_kb_avail();
	kb_swap_avail = get_kb_swap_avail();
	kb_min = (kb_main_total + kb_swap_total)/100*MIN_AVAIL_PERCENT;

	fprintf(stderr, "mem total:  %5lu MiB\n", kb_main_total/1024);
	fprintf(stderr, "mem avail:  %5lu MiB\n", kb_avail/1024);
	fprintf(stderr, "swap total: %5lu MiB\n", kb_swap_total/1024);
	fprintf(stderr, "swap avail: %5lu MiB\n", kb_swap_avail/1024);
	fprintf(stderr, "threshold:  %5lu MiB\n", kb_min/1024);

	/* Dry-run oom kill to make sure stack grows to maximum size before
	 * calling mlockall()
	 */
	handle_oom(procdir, 0);

	if(mlockall(MCL_FUTURE)!=0)
	{
		fprintf(stderr, "Error: Could not lock memory: %s\n", strerror(errno));
		exit(10);
	}

	unsigned char c=1; // So we do not print another status line immediately
	while(1)
	{
		kb_avail = get_kb_avail();
		kb_swap_avail = get_kb_swap_avail();

		if(c % 10 == 0)
		{
			GET_FORMATTED_TIME
			printf("%s avail: %5lu MiB swap: %5lu MiB\n", time_str, kb_avail/1024, kb_swap_avail/1024);
			/*printf("kb_main_free: %lu kb_main_buffers: %lu kb_main_cached: %lu kb_main_shared: %lu\n",
				kb_main_free, kb_main_buffers, kb_main_cached, kb_main_shared);
			*/
			c=0;
		}
		c++;

		//if(kb_avail < kb_min && kb_swap_avail < kb_min)
		if(kb_avail + kb_swap_avail < kb_min)
		{
			GET_FORMATTED_TIME
			fprintf(stderr, "%s Out of memory!     avail: %5lu MiB + swap: %5lu MiB < min: %5lu MiB\n",
				time_str, kb_avail/1024, kb_swap_avail/1024, kb_min/1024);

			handle_oom(procdir, 9);
			oom_cnt++;

			// Let's check if it worked immediately
			kb_avail = get_kb_avail();
			kb_swap_avail = get_kb_swap_avail();
			GET_FORMATTED_TIME
			fprintf(stderr, "%s Memory after kill: avail: %5lu MiB + swap: %5lu MiB\n",
				time_str, kb_avail/1024, kb_swap_avail/1024, kb_min/1024);

			// On one occasion, kill_by_rss was called three times, on three different processes, when only the first really needed to be killed.
			usleep(10*1000*1000); // 10 seconds

			// Let's check if waiting makes a difference.
			kb_avail = get_kb_avail();
			kb_swap_avail = get_kb_swap_avail();
			GET_FORMATTED_TIME
			fprintf(stderr, "%s Memory after wait: avail: %5lu MiB + swap: %5lu MiB\n",
				time_str, kb_avail/1024, kb_swap_avail/1024, kb_min/1024);
		}

		usleep(100000); // 100ms
	}
	
	return 0;
}
