/* Authorization groups standalone */

#include <stdio.h>

#include <ldap.h>
#include <lber.h>
#include <sasl/sasl.h>
#include <sys/time.h>

#include "ldaplib.h"

#define PRINTF if (0) printf

char *prog;

void usage() 
{
   fprintf(stderr, "usage: %s -CA cafile -C certfile [-K keyfile]\n", prog);
   fprintf(stderr, "        -g group -u userid\n");
   exit (9);
}

set_x509(LdapCfg cfg, char *ca, char *crt, char *key)
{
  cfg->host = "groups.u.washington.edu";
  cfg->port = 389;
  cfg->sslport = 389;

  cfg->certdb = ca;
  cfg->bindcrt = crt;
  if (key) cfg->bindkey = key;
  else cfg->bindkey = crt;
}


main(int argc, char**argv)
{
  LdapCfg cfg = new_ldap_cfg();
  void *L;
  char **types;
  char *id = "fox";
  char *grp = NULL;
  char *crs = NULL;
  char *crsonr = NULL;
  char *cafile = NULL;
  char *crtfile = NULL;
  char *keyfile = NULL;
  int r;
  int rc = 0;

  prog = argv[0];
  while (--argc) {
     argv++;
     if (!strcmp(argv[0],"-CA")) {
        if (--argc<=0) usage();
        cafile = (++argv)[0];
     } else if (!strcmp(argv[0],"-C")) {
        if (--argc<=0) usage();
        crtfile = (++argv)[0];
     } else if (!strcmp(argv[0],"-K")) {
        if (--argc<=0) usage();
        keyfile = (++argv)[0];
     } else if (!strcmp(argv[0],"-g")) {
        if (--argc<=0) usage();
        grp = (++argv)[0];
     } else if (!strcmp(argv[0],"-u")) {
        if (--argc<=0) usage();
        id = (++argv)[0];
     }
  }

  if (grp && id) {
     set_x509(cfg, cafile, crtfile, keyfile);

     PRINTF("Connecting via to %s\n", cfg->host);
     L = uw_auth_initialize(cfg);

     rc = 0;

     if (L) {
        PRINTF("Initialize OK\n");
     
        PRINTF("Checking if %s is in %s\n", id, grp);
        rc = uw_auth_chk_in_group(L, cfg, id, grp);
        PRINTF("... %s\n", rc?"yes":"no");

     } else {
        PRINTF("Initialize failed\n");
     }
  } else usage();
     
  exit (1-rc);
}
