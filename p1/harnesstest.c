#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "securitylevel/securitylevel.h"

#define TOP_SECRET 4
#define SECRET 3
#define CLASSIFIED 2
#define SENSITIVE 1
#define UNCLASSIFIED 0

void super_proc(int child_pipe, int child_pid);
void user_proc(int parent_pipe, int child_pipe, int child_pid);
void child_proc(int parent_pipe, int parent_pid);

char *level_names[5] = { "UNCLASSIFIED", "SENSITIVE", "CLASSIFIED", "SECRET", "TOP SECRET" };

int harness_get(int pid)
{
    errno = 0;
    int retval;
    int* params = retrieve_get_security_params(pid);
    int num_params = params[1];
    switch (num_params)
    {
        case 0:
            retval = syscall(params[0]);
            break;
        case 1:
            retval = syscall(params[0],params[2]);
            break;
        case 2:
            retval = syscall(params[0],params[2],params[3]);
            break;
    }

    free(params);

    return interpret_get_security_result(retval);
}

int harness_set(int pid, int target_level)
{
    errno = 0;
    int retval;
    int* params = retrieve_set_security_params(pid,target_level);
    int num_params = params[1];
    switch (num_params)
    {
        case 0:
            retval = syscall(params[0]);
            break;
        case 1:
            retval = syscall(params[0],params[2]);
            break;
        case 2:
            retval = syscall(params[0],params[2],params[3]);
            break;
    }

    free(params);

    return interpret_set_security_result(retval); 
}

int attempt_change(int pid, int target_level, char *from, char *to, bool expected)
{
    int result;
    int security_level;

    printf("Target %s level: [%d]. Source %s level: [%d].\n", to, harness_get(pid), from, harness_get(getpid()));
    printf("Set %s level to %s [%d] (from %s)...", to, level_names[target_level], target_level, from);
    result = harness_set(pid, target_level);

    if (result == -1)
        printf("Failure! [%s]\n", expected ? "Incorrect" : "Correct");
    else
        printf("Success! [%s]\n", expected ? "Correct" : "Incorrect");

    security_level = harness_get(pid);

    if (security_level == target_level)
        printf("Target acquired target security level. [%s]\n", expected ? "Correct" : "Incorrect");
    else
        printf("Target did not acquire target security level. [%s]\n", expected ? "Incorrect" : "Correct");

    return result;
}

void child_proc(int parent_pipe, int parent_pid)
{
    char buf;
    read(parent_pipe, &buf, 1);

    printf("\n++++Beginning child process tests.++++\n");
    attempt_change(parent_pid, SENSITIVE, "child_proc", "user_proc", true);
    attempt_change(parent_pid, CLASSIFIED, "child_proc", "user_proc", true);
    attempt_change(parent_pid, TOP_SECRET, "child_proc", "user_proc", false);
    attempt_change(parent_pid, SECRET, "child_proc", "user_proc", true);
    attempt_change(parent_pid, SENSITIVE, "child_proc", "user_proc", false);
    fflush(stdout);
}

void user_proc(int parent_pipe, int child_pipe, int child_pid)
{
    int status;
    char buf;

    // Wait for the signal from the startup proc before continuing.
    read(parent_pipe, &buf, 1);

    // Make adjustments to the lower security level process.
    printf("\n++++Beginning user mode (high security) tests.++++\n");
    attempt_change(child_pid, CLASSIFIED, "user_proc", "child_proc", true);
    attempt_change(child_pid, SENSITIVE, "user_proc", "child_proc", true);
    attempt_change(child_pid, TOP_SECRET, "user_proc", "child_proc", false);
    attempt_change(child_pid, SECRET, "user_proc", "child_proc", true);

    // Demote ourselves for the next round of checks.
    attempt_change(getpid(), CLASSIFIED, "user_proc", "user_proc", true);
    fflush(stdout);

    // Give child the OK to continue (by writing to the pipe).
    write(child_pipe, "+", 1);
    sleep(1);
}

void spinoff_proc(int parent)
{
    int child_pid, parent_pid;
    int pipeset[2];

    // Lower this process to normal user level (if elevated), then wait for su proc.
    setuid(1000);

    // Once super user proc has given us access, spin off a child user process.
    if (pipe(pipeset) == -1)
    {
        perror("Failed to create child process pipe (fatal)");
        exit(EXIT_FAILURE);
    }

    parent_pid = getpid();
    child_pid = fork();

    if (child_pid == -1)
    {
        perror("Failed to fork child process (fatal)");
        exit(EXIT_FAILURE);
    }
    else if (child_pid == 0)
    {
        // Grandchild.
        close(pipeset[1]);
        child_proc(pipeset[0], parent_pid);
    }
    else
    {
        close(pipeset[0]);
        user_proc(parent, pipeset[1], child_pid);
    }
}

void super_proc(int child_pipe, int child_pid)
{
    int status;

    printf("\n++++Beginning super user mode procedure.++++\n");

    if (geteuid() != 0)
        printf("WARNING: initial process is not in superuser mode.\n");

    // Wait for the spinoff process to get started.
    sleep(1);

    attempt_change(child_pid, SECRET, "startup_proc", "user_proc", true);

    // Give user proc the OK to continue (by writing to the pipe).
    printf("Enabling user processes.\n");
    fflush(stdout);
    write(child_pipe, "+", 1);
    sleep(2);
}

int main(int argc, char** argv)
{
    int pipeset[2];
    int child_pid;
 
    if (pipe(pipeset) == -1)
    {
        perror("Failed to create user process pipe (fatal)");
        exit(EXIT_FAILURE);
    }

    child_pid = fork();

    if (child_pid == -1)
    {
        perror("Failed to fork user process (fatal)");
        exit(EXIT_FAILURE);
    }
    else if (child_pid == 0)
    {
        close(pipeset[1]);
        spinoff_proc(pipeset[0]);
    }
    else
    {
        close(pipeset[0]);
        super_proc(pipeset[1], child_pid);
    }
}
