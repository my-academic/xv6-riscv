#include "kernel/param.h"
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int main(int argc, char *argv[])
{
  // int i;
  // char *nargv[MAXARG];

  int ticket = atoi(argv[1]);
  if (ticket == 0)
  {
    fprintf(2, "Usage: %s num_of_tickets [num_of_tickets > 0]\n", argv[0]);
    exit(1);
  }

  // handle negative number of tickets
  if (setticket(ticket) < 0)
  {
    fprintf(2, "%s: ticket set failed\n", argv[0]);
    exit(1);
  }


  while(1);
  // while(fork() != 0){
  //   // parent
  //   sleep(1);
  // }
  exit(0);
}