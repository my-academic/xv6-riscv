#include "kernel/param.h"
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/pstat.h"

int main(int argc, char *argv[])
{
  // int i;
  // char *nargv[MAXARG];

  //   if(ticket == 0) {
  //     fprintf(2, "Usage: %s num_of_tickets [num_of_tickets > 0]\n", argv[0]);
  //     exit(1);
  //   }

  // handle negative number of tickets

  struct pstat pstat;
  printf("%d\n", &pstat);

  while (fork() > 0)
  {
    if (getpinfo(&pstat) < 0)
    {
      fprintf(2, "%s: ticket set failed\n", argv[0]);
      exit(1);
    }

    for (int i = 0; i < NPROC; i++)
    {
      if (pstat.inuse[i] == 1)
      {
        printf("id = %d\t inuse = %d\t original ticket = %d\t current ticket = %d\t time slice=%d\n", pstat.pid[i], pstat.inuse[i], pstat.tickets_original[i], pstat.tickets_current[i], pstat.time_slices[i]);
      }
    }
    sleep(20);
  }

  char *nargv[MAXARG];
  nargv[0] = "testticket";
  nargv[1] = "50";

  exec("testticket", nargv);

  // while(1);

  // for(i = 2; i < argc && i < MAXARG; i++){
  //   nargv[i-2] = argv[i];
  // }
  // exec(nargv[0], nargv);
  exit(0);
}