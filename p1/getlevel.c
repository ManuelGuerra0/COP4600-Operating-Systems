/* getlevel.c
	by Jeremiah Blanchard
	2017/09/25
	allows shell command to read security level for project 1 in COP4600
 */

#include <stdio.h>
#include <unistd.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include "securitylevel/securitylevel.h"

#define ARGCNT 2
#define HELPMSG "Usage: getlevel <PID>\n"

int main(int argc, char** argv)
{
    int pid, level;
    int retval;

    // check and get command line arguments
    if (argc < ARGCNT)
    {
        printf("%s", "No PID\n");
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

    // attempt call
    level = get_security_level(pid);
    if (level == -1)
    {
        printf("%s", "get_security_level failed\n");
        printf("%s", HELPMSG);
        return 0;
    }

    // print result if success
    printf("Successfully retrieved security level: %d\n", level);
    return 0;
}


