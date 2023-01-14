#include "kernel/param.h"
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  // int i;
  // char *nargv[MAXARG];

//   if(ticket == 0) {
//     fprintf(2, "Usage: %s num_of_tickets [num_of_tickets > 0]\n", argv[0]);
//     exit(1);
//   }

  // handle negative number of tickets

  struct pstat pstat;

  if (getpinfo(&pstat) < 0) {
    fprintf(2, "%s: ticket set failed\n", argv[0]);
    exit(1);
  }

  while(1);
  
  // for(i = 2; i < argc && i < MAXARG; i++){
  //   nargv[i-2] = argv[i];
  // }
  // exec(nargv[0], nargv);
  exit(0);
}