/* setlevel.c
	by Jeremiah Blanchard
	2017/09/25
	allows shell command to set security level for project 1 in COP4600
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include "securitylevel/securitylevel.h"

#define ARGCNT 3
#define HELPMSG "Usage: setlevel <PID> <level>\n"

int main(int argc, char** argv)
{
    int pid, level;
    int retval;

    // check and get command line arguments
    if (argc < ARGCNT)
    {
        printf("%s", "No PID or level\n");
        printf("%s", HELPMSG);
        return 0;
    }

    retval = sscanf(argv[1], "%d", &pid);
    if (retval != 1)
    {
        printf("%s", "Bad PID\n");
        printf("%s", HELPMSG);
        return 0;
    }

    retval = sscanf(argv[2], "%d", &level);
    if (retval != 1)
    {
        printf("%s", "Bad level\n");
        printf("%s", HELPMSG);
        return 0;
    }

    // advise on invalid level
    if (level < 0)
    {
        printf("%s", "Bad level: must be non-negative\n");
    }

    // advise on non-root process
    retval = geteuid();
    if (retval != 0)
    {
        printf("%s", "NOTE: not root user\n");
    }

    // attempt call
    level = set_security_level(pid, level);
    if (level == -1)
    {
        printf("%s", "set_security_level failed\n");
        printf("%s", HELPMSG);
        return 0;
    }

    // print result if success
    printf("Successfully set security level: %d\n", level);
    return 0;
}
