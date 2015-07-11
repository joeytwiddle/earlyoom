/* Check available memory and swap in a loop and start killing
 * processes if they get too low */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
#include <regex.h>

//#include "sysinfo.h"

#include "meminfo.h"
#include "kill.h"

// The excluded regexp allows us to mark some processes as too precious to kill.
// For example, closing the core google-chrome process will close all the tabs, when there are likely just a few tabs that can be killed to relclaim a lot of memory.  So we use the regexp to match just the browser process (no args = "$"), but not the tab processes (tend to have args "--type=renderer").
// DONE: Perhaps "never kill" is not the best rule for this case.  We could instead divide the score of matching processes by 32, so they are less likely to be killed prematurely, but will ultimately be considered if needed.
// CONSIDER: We could opt for a different approach in this case.  We could increase the score of specific processes, e.g. "chrome --type=renderer" so that they will be more likely to be reclaimed.  Although the multiplier may need to be over 5 for a large chrome tab to beat the firefox process.  Perhaps firefox and chrome base processes could be given reduced score because we expect them to be large but they are important.  (OTOH, they tend to recover reasonably from being killed, perhaps better than other apps.)
// NOTE: solutions based on process name will never be ideal: a malicious process could rename itself to evade consideration.  Ideas for alternative approaches would be welcomed!  (The kernel-space oom killer's exclusions requires PIDs be specified, which is powerful and accurate, but not very easy to use.)
// TODO: Slightly reduce score for recent processes.  (Is this stored somewhere in /proc/<pid>/...?)  Because I found recently that earlyoom killed the google-chrome tabset that I was working on, when it probably would have been better to close some older tabsets.

// I want to match all init, sshd and firefox processes, but ONLY the initial chrome process.  Chrome tab processes and extension processes will be treated normally.
char *excluded_cmdlines_pattern = "(^|/)(((init|X|sshd|firefox)( .*|$))|chrome|chromium-browser)$";
regex_t excluded_cmdlines_regexp;

int enable_debug = 0;

int main(int argc, char *argv[])
{
	int kernel_oom_killer = 0;
	unsigned long oom_cnt = 0;
	/* If the available memory goes below this percentage, we start killing
	 * processes. 10 is a good start. */
	int mem_min_percent = 10, swap_min_percent = 10;
	long mem_min, swap_min; /* Same thing in kiB */
	int ignore_oom_score_adj = 0;

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

	/* request line buffering for stdout - otherwise the output
	 * may lag behind stderr */
	setlinebuf(stdout);

	fprintf(stderr, "earlyoom %s\n", GITVERSION);

	if(chdir("/proc")!=0)
	{
		perror("Could not cd to /proc");
		exit(4);
	}

	DIR *procdir = opendir(".");
	if(procdir==NULL)
	{
		perror("Could not open /proc");
		exit(5);
	}

	int c;
	while((c = getopt (argc, argv, "m:s:kidh")) != -1)
	{
		switch(c)
		{
			case 'm':
				mem_min_percent = strtol(optarg, NULL, 10);
				if(mem_min_percent <= 0) {
					fprintf(stderr, "-m: Invalid percentage\n");
					exit(15);
				}
				break;
			case 's':
				swap_min_percent = strtol(optarg, NULL, 10);
				if(swap_min_percent <= 0 || swap_min_percent > 100) {
					fprintf(stderr, "-s: Invalid percentage\n");
					exit(16);
				}
				break;
			case 'k':
				kernel_oom_killer = 1;
				fprintf(stderr, "Using kernel oom killer\n");
				break;
			case 'i':
				ignore_oom_score_adj = 1;
				break;
			case 'd':
				enable_debug = 1;
				break;
			case 'h':
				fprintf(stderr,
					"Usage: earlyoom [-m PERCENT] [-s PERCENT] [-k|-i] [-h]\n"
					"-m ... set available memory minimum to PERCENT of total (default 10 %%)\n"
					"-s ... set free swap minimum to PERCENT of total (default 10 %%)\n"
					"-k ... use kernel oom killer instead of own user-space implementation\n"
					"-i ... user-space oom killer should ignore positive oom_score_adj values\n"
					"-d ... enable debugging messages\n"
					"-h ... this help text\n");
				exit(1);
			case '?':
				exit(13);
		}
	}

	if(kernel_oom_killer && ignore_oom_score_adj) {
		fprintf(stderr, "Kernel oom killer does not support -i\n");
		exit(2);
	}

	struct meminfo m = parse_meminfo();
	mem_min = m.MemTotal * mem_min_percent / 100;
	swap_min = m.SwapTotal * swap_min_percent / 100;

	fprintf(stderr, "mem total: %lu MiB, min: %lu MiB (%d %%)\n",
		m.MemTotal / 1024, mem_min / 1024, mem_min_percent);
	fprintf(stderr, "swap total: %lu MiB, min: %lu MiB (%d %%)\n",
		m.SwapTotal / 1024, swap_min / 1024, swap_min_percent);

	/* Dry-run oom kill to make sure stack grows to maximum size before
	 * calling mlockall()
	 */
	handle_oom(procdir, 0, kernel_oom_killer, ignore_oom_score_adj);

	if(mlockall(MCL_FUTURE)!=0)
	{
		perror("Could not lock memory");
		exit(10);
	}

	c = 1; // Start at 1 so we do not print another status line immediately
	while(1)
	{
		m = parse_meminfo();

		if(c % 10 == 0)
		{
			GET_FORMATTED_TIME
			printf("%s mem avail: %5lu MiB, swap free: %5lu MiB\n",
				time_str, m.MemAvailable / 1024, m.SwapFree / 1024);
			c=0;
		}
		c++;

		if(m.MemAvailable <= mem_min && m.SwapFree <= swap_min)
		{
			GET_FORMATTED_TIME
			fprintf(stderr, "%s Out of memory!     avail: %lu MiB < min: %lu MiB\n",
				time_str, m.MemAvailable / 1024, mem_min / 1024);
			handle_oom(procdir, 9, kernel_oom_killer, ignore_oom_score_adj);
			oom_cnt++;

			// Let's check if it worked immediately
			if (enable_debug)
			{
				m = parse_meminfo();
				GET_FORMATTED_TIME
				fprintf(stderr, "%s Memory after kill: avail: %5lu MiB + swap: %5lu MiB\n",
					time_str, m.MemAvailable / 1024, m.SwapFree / 1024, mem_min / 1024);
			}

			// On one occasion, kill_by_rss was called three times, on three different processes, when only the first really needed to be killed.
			usleep(10*1000*1000); // 10 seconds

			// Let's check if waiting makes a difference.
			if (enable_debug)
			{
				m = parse_meminfo();
				GET_FORMATTED_TIME
				fprintf(stderr, "%s Memory after wait: avail: %5lu MiB + swap: %5lu MiB\n",
					time_str, m.MemAvailable / 1024, m.SwapFree / 1024, mem_min / 1024);
			}
		}

		usleep(100000); // 100ms
	}
	
	return 0;
}
