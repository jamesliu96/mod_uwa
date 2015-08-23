/* ========================================================================
 * Copyright (c) 2006-2007 The University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

/* UW authorization module (ldap)
   see: uwa.html 
 */

#include <pwd.h>
#include <grp.h>
#include <sys/types.h>

#include "config.h"

/* MOD_UWA_DEBUG only for stdout with httpd '-X' option */
#if defined(MOD_UWA_DEBUG)
#define PRINTF if (1) printf
#else 
#define PRINTF if (0) printf
#endif

#include "httpd.h"
#include "http_log.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_core.h"
/* #include "ap_alloc.h" */

#ifdef APACHE2
typedef apr_pool_t pool;
typedef apr_table_t table;
#endif

#include "uwa_crypt.h"

/* default cookie password */
#define COOKIE   "UA_Auth"

module uwa_module;

#include "ldaplib.h"

char *uwa_cookie_id (request_rec * r);

#define TIMEOUT_TIME 3600 /* 1 hour */


#ifdef APACHE2

#include "apr_strings.h"

#define MY_LOG_DEBUG APLOG_MARK,APLOG_DEBUG,0
#define MY_LOG_INFO  APLOG_MARK,APLOG_INFO,0
#define MY_LOG_ERR   APLOG_MARK,APLOG_ERR,0
#define MY_LOG_EMERG APLOG_MARK,APLOG_EMERG,0
#define USER user
#define AUTH_TYPE ap_auth_type

#define ap_palloc apr_palloc
#define ap_pcalloc apr_pcalloc
#define ap_pstrcat apr_pstrcat
#define ap_pstrdup apr_pstrdup
#define ap_pstrndup apr_pstrndup
#define ap_table_add apr_table_add
#define ap_table_get apr_table_get
#define ap_table_set apr_table_set
#define ap_table_setn apr_table_setn
#define ap_table_merge apr_table_merge
#define ap_make_table apr_table_make
#define ap_overlay_tables apr_table_overlay

#else /* apache 1.3 */

#define MY_LOG_DEBUG APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO
#define MY_LOG_INFO  APLOG_MARK,APLOG_INFO|APLOG_NOERRNO
#define MY_LOG_ERR   APLOG_MARK,APLOG_ERR
#define MY_LOG_EMERG APLOG_MARK,APLOG_EMERG|APLOG_NOERRNO
#define USER connection->user
#define AUTH_TYPE connection->ap_auth_type
#define APR_SUCCESS HTTP_OK
#define AP_RAW_ARGS func
#define AP_TAKE1 func
#define AP_FLAG func

#endif /* which apache */

/* uwa configuration */

/* define UNIQUE_CR_LDAP if the groups and courses server are different */
#undef UNIQUE_CR_LDAP

#define PR_LDAP 0       /* person ldap */
#define GR_LDAP 1       /* groups ldap */
#ifdef UNIQUE_CR_LDAP
#define CR_LDAP 2       /* courses ldap */
#define NLDAP 3
#else
#define CR_LDAP 1       /* courses ldap same as groups */
#define NLDAP 2
#endif


typedef struct {
   int  enabled;        /* if 0, don't use */
   int  needssl;        /* is ssl needed */
   int  crsown;         /* must courses be self-owned */
   char *cookie;        /* uwa cookie name */
   LdapConfig *cfg[NLDAP];  /* ldap services */
} uwa_config_rec;

/* Apache 2.2.x headers must be accumulated and set in the output filter.
   Apache 2.0.49+ also supports the filters as well.
   In Apache 1.3.x and lesser 2.0.x we write the headers directly. */

#if defined(APACHE2) && AP_MODULE_MAGIC_AT_LEAST(20020903,6)
#define UWA_DEFERRED_HEADERS

/* Append add the entries in 'src' to the 'dest' table */
static void append_to_table(request_rec *r, apr_table_t *dest, apr_table_t *src)
{
   const apr_array_header_t *srce = apr_table_elts(src);
   int i;

   for (i=0; i<srce->nelts; i++) {
      apr_table_entry_t *ent = &((apr_table_entry_t *) (srce->elts))[i];
      ap_log_rerror (MY_LOG_DEBUG, r, "uwa adding header %s", ent->key);
      apr_table_add(dest, ent->key, ent->val);
   }
}
#endif


#define MAX_CACHE  32  /* max cached request lines per user */
#define MAX_CACHEB 148 /* MAX_CACHE*sizeof(u_long)+20 (see ctext/etext) */
#define MAX_ID 20      /* max that we'll keep */

/* per request module stuff */
typedef struct {
  u_long uhash[MAX_CACHE];  /* auth hash cache */
  int nuhash;
#ifdef UWA_DEFERRED_HEADERS
   table *headers_out;
#endif
} uwa_request_rec;

/* Authorization computational data */

/* auth commands */
#define AC_REQUIRE 2
#define AC_EXCLUDE 3

/* auth token codes */
#define AT_ROOT    0
#define AT_ID      1
#define AT_TYPE    2
#define AT_GROUP   3
#define AT_COURSE  4
#define AT_AND     5
#define AT_OR      6
#define AT_NOT     7
#define AT_LP      8
#define AT_RP      9
#define AT_VALID  10
#define AT_VALUE  11
#define AT_UGROUP 12
#define AT_END    13

typedef struct AuthTok__ {
   struct AuthTok__ *next;
   int tok;
   char *text;
} AuthTok_, *AuthTok;


/* one of these per authorization line */

typedef struct AuthSet__ {
   struct AuthSet__ *next;
   AuthTok toks;
   unsigned long hash;
} AuthSet_, *AuthSet;

/* one of these per dir conf section */

typedef struct {
   int active;
   int partial;
   AuthSet auth;
   pool *sp;
   int implor;
} uwa_dir_config_rec;

/* caching hash function */

#define HASH(h,t,k) h+=t*13*k++

/* -------------------------------------- */


/* Does nothing if alread connected */
static int connect_to_ldap(request_rec *r, LdapConfig *cfg)
{
   if (cfg->ldap) return (1);
   ap_log_rerror(MY_LOG_INFO, r, " pid %d connecting to ldap at %s:%d (%x)\n",
      getpid(), cfg->host, cfg->port, cfg->ldap);
   return (uw_auth_connect(cfg, r));
}


#ifdef APACHE2
static int uwa_init(pool *p, pool *plog, pool *ptemp, server_rec *s) {
  PRINTF("UWA post-config\n");
   ap_add_version_component(p, MOD_UWA_NAME "/" MOD_UWA_VERSION);
   uwa_crypt_init();
   return OK;
#else
static void uwa_init(server_rec *s, pool *p) {
   ap_add_version_component(MOD_UWA_NAME "/" MOD_UWA_VERSION);
   uwa_crypt_init();
   return;
#endif
}

static int uwa_pre_config(pool *p, pool *plog, pool *ptemp) {
  uwa_crypt_init();
  PRINTF("UWA pre-config\n");
  return OK;
}

/* Start of a request.  If using filters make the request record. */

static int uwa_post_read (request_rec * r)
{
    uwa_request_rec *rr = ap_pcalloc(r->pool, sizeof(uwa_request_rec));
    
    ap_log_rerror(MY_LOG_DEBUG, r, "uwa_post_read: sr=%x", r->server);
    rr->nuhash = 0;
#ifdef UWA_DEFERRED_HEADERS
    ap_set_module_config (r->request_config, &uwa_module, rr);
    rr->headers_out = ap_make_table(r->pool, 3);

    /* If this is a forwarded request, copy our headers from the parent. */
    if (r->prev) {
       int n;
       uwa_request_rec *prr = (uwa_request_rec *) ap_get_module_config (r->prev->request_config,
                                                     &uwa_module);
       if (prr) {
          n = apr_table_elts(prr->headers_out)->nelts;
          ap_log_rerror (MY_LOG_DEBUG, r, "uwa of: forwarding %d output headers to redirect request", n);
          if (n) append_to_table(r, rr->headers_out, prr->headers_out);

          for (n=0; n<prr->nuhash; n++) rr->uhash[n] = prr->uhash[n];
          rr->nuhash = prr->nuhash;
       }
    }

#endif

    return DECLINED;
}

/* Fixups.  By this time we're done with auth */

static int uwa_fixups (request_rec * r)
{
   void *server_conf = r->server->module_config;
   uwa_config_rec *uwa = (uwa_config_rec *)
                ap_get_module_config (server_conf, &uwa_module);
   int i;
    
   PRINTF("UWA: fixups\n");
   for (i=0;i<NLDAP;i++) {
      if (uwa->cfg[i]->ldap) {
         ap_log_rerror(MY_LOG_DEBUG, r, "uwa fixups: closing %d", i);
         uw_auth_disconnect(uwa->cfg[i]);
      }
   }
   return DECLINED;
}

static void *
create_uwa_config (pool *p, struct server_rec *d)
{
  uwa_config_rec *ua = (uwa_config_rec *) ap_pcalloc (p, sizeof (uwa_config_rec));
  int i;

  PRINTF("<create_uwa_config>\n");
  uwa_crypt_seed();
  ua->needssl = 1;
  ua->enabled = 0;
  ua->crsown = 0;
  ua->cookie = ap_pstrdup(p, COOKIE);
  for (i=0; i<NLDAP; i++) ua->cfg[i] = new_ldap_cfg();
  ap_log_error(MY_LOG_INFO, d, "create_uwa_config");
  return ua;
}


const char *set_uwa_active (cmd_parms *cmd, void *dummy)
{
   void *server_conf = cmd->server->module_config;
   uwa_config_rec *ua = (uwa_config_rec *) ap_get_module_config(server_conf, &uwa_module);

   PRINTF("<set_uwa_active>\n");
   ua->enabled = 1;
   return NULL;
}

/* Set an ldapserver name and port */
static const char *set_ldapserver (cmd_parms *cmd, const char *hp, int typ)
{
    void *server_conf = cmd->server->module_config;
    uwa_config_rec *ua = (uwa_config_rec *) ap_get_module_config(server_conf, &uwa_module);
    char *p;
    LdapConfig *cfg = ua->cfg[typ];

    PRINTF("<set_ldapserver: %c>\n", typ);
    if (!ua->enabled) set_uwa_active(cmd, NULL);

    cfg->host = ap_pstrdup(cmd->pool, hp);
    if (p=strchr(cfg->host,':')) *p = '\0';
    if (p=strchr(hp,':')) {
      cfg->port = atoi(p+1);
      if (cfg->port<=0) {
        printf("ldap port < 0 !!");   /* should do log */
        exit (1);
      }
    }
    PRINTF("  ldap(%d) = %s:%d\n", typ, cfg->host, cfg->port);
    return NULL;
}

/* Set all ldapserver name and port */
const char *set_uwa_ldapserver (cmd_parms *cmd, void *dummy, const char *opt1)
{
   set_ldapserver(cmd, opt1, PR_LDAP);
   set_ldapserver(cmd, opt1, GR_LDAP);
   set_ldapserver(cmd, opt1, CR_LDAP);
   return (NULL);
}
/* Set the person ldapserver name and port */
const char *set_uwa_pr_ldapserver (cmd_parms *cmd, void *dummy, const char *opt1)
{
   return (set_ldapserver(cmd, opt1, PR_LDAP));
}
/* Set the group ldapserver name and port */
const char *set_uwa_gr_ldapserver (cmd_parms *cmd, void *dummy, const char *opt1)
{
   return (set_ldapserver(cmd, opt1, GR_LDAP));
}
/* Set the course ldapserver name and port */
const char *set_uwa_cr_ldapserver (cmd_parms *cmd, void *dummy, const char *opt1)
{
   return (set_ldapserver(cmd, opt1, CR_LDAP));
}


/* Set the ca database for server cert verification */
const char *set_uwa_certdb (cmd_parms *cmd, void *dummy, const char *opt1)
{
   void *server_conf = cmd->server->module_config;
   uwa_config_rec *ua = (uwa_config_rec *)
        ap_get_module_config(server_conf, &uwa_module);
   char *cdb;

   PRINTF("<set_uwa_certdb>\n");
   if (!ua->enabled) set_uwa_active(cmd, dummy);

   /* all set by same command.  Could have separate values sometime. */
   cdb = ap_pstrdup(cmd->pool, opt1);
   ua->cfg[PR_LDAP]->certdb = cdb;
   ua->cfg[GR_LDAP]->certdb = cdb;
   ua->cfg[CR_LDAP]->certdb = cdb;
   PRINTF("  certdb = %s\n", cdb);
   return NULL;
}

/* Set our authentication cert */
const char *set_uwa_bindcrt (cmd_parms *cmd, void *dummy, const char *opt1)
{
    void *server_conf = cmd->server->module_config;
     uwa_config_rec *ua = (uwa_config_rec *)
        ap_get_module_config(server_conf, &uwa_module);
   char *cdb;

   PRINTF("<set_uwa_bindcrt>\n");

   cdb = ap_pstrdup(cmd->pool, opt1);
   ua->cfg[PR_LDAP]->bindcrt = cdb;
   ua->cfg[GR_LDAP]->bindcrt = cdb;
   ua->cfg[CR_LDAP]->bindcrt = cdb;
   PRINTF("  bindcrt = %s\n", cdb);
   return NULL;
}

/* Set our authentication cert's key */
const char *set_uwa_bindkey (cmd_parms *cmd, void *dummy, const char *opt1)
{
    void *server_conf = cmd->server->module_config;
     uwa_config_rec *ua = (uwa_config_rec *)
        ap_get_module_config(server_conf, &uwa_module);
   char *cdb;

   PRINTF("<set_uwa_bindkey>\n");

   cdb = ap_pstrdup(cmd->pool, opt1);
   ua->cfg[PR_LDAP]->bindkey = cdb;
   ua->cfg[GR_LDAP]->bindkey = cdb;
   ua->cfg[CR_LDAP]->bindkey = cdb;
   PRINTF("  bindkey = %s\n", cdb);
   return NULL;
}

/* Set the user and password for basic ldap auth */
const char *set_uwa_bindinfo (cmd_parms *cmd, void *dummy, const char *opt1)
{
    char rec[1024];
    FILE *f;
    void *server_conf = cmd->server->module_config;
     uwa_config_rec *ua = (uwa_config_rec *)
        ap_get_module_config(server_conf, &uwa_module);
    char *p;
   char *dp;

   PRINTF("<set_uwa_bindinfo>\n");
   if (!ua->enabled) set_uwa_active(cmd, dummy);

   f = fopen(opt1,"r");
   if (f) {
    while (fgets(rec, 1024, f)) {
      PRINTF("bi=%s", rec);
      if (rec[0]=='#') continue;
      if (p=strchr(rec,'\n')) *p = '\0';
      if (!ua->cfg[PR_LDAP]->binddn) {
         char *d = ap_pstrdup(cmd->pool, rec);
         ua->cfg[PR_LDAP]->binddn = d;
         ua->cfg[GR_LDAP]->binddn = d;
         ua->cfg[CR_LDAP]->binddn = d;
      } else {
         char *d = ap_pstrdup(cmd->pool, rec);
         ua->cfg[PR_LDAP]->bindpw = d;
         ua->cfg[GR_LDAP]->bindpw = d;
         ua->cfg[CR_LDAP]->bindpw = d;
         break;
      }
    }
    fclose(f);
   } else {
      perror("bindinfo");
      exit (1);
   }
   PRINTF("  bind = %s\n", ua->cfg[PR_LDAP]->binddn);
   return NULL;
}

/* Set to use kerberos auth - in ticket cache */
const char *set_uwa_k5 (cmd_parms *cmd, void *dummy)
{
    void *server_conf = cmd->server->module_config;
     uwa_config_rec *ua = (uwa_config_rec *)
        ap_get_module_config(server_conf, &uwa_module);

   ua->cfg[PR_LDAP]->gssapi = 1;
   ua->cfg[GR_LDAP]->gssapi = 1;
   ua->cfg[CR_LDAP]->gssapi = 1;
   return NULL;
}

const char *set_uwa_cookie (cmd_parms *cmd, void *dummy,
   const char *opt1)
{
    void *server_conf = cmd->server->module_config;
     uwa_config_rec *ua = (uwa_config_rec *)
        ap_get_module_config(server_conf, &uwa_module);

   if (!ua->enabled) set_uwa_active(cmd, dummy);

    if (strlen(opt1)<63) {
       ua->cookie = ap_pstrdup(cmd->pool, opt1);
       PRINTF("UW authorize cookie = %s\n", opt1);
    }
     
    return NULL;
}

char *uwa_cookiename(request_rec *r)
{
    void *server_conf = r->server->module_config;
     uwa_config_rec *ua = (uwa_config_rec *)
        ap_get_module_config(server_conf, &uwa_module);

    return (ua->cookie);
}

const char *set_uwa_nossl (cmd_parms *cmd, void *dummy)
{
    void *server_conf = cmd->server->module_config;
     uwa_config_rec *ua = (uwa_config_rec *)
        ap_get_module_config(server_conf, &uwa_module);

  PRINTF("<set_uwa_nossl>\n");
     ua->needssl = 0;
    return NULL;
}

static void *
create_uwa_dir_config (pool * p, char *d)
{
  uwa_dir_config_rec *ua = (uwa_dir_config_rec *)
      ap_pcalloc (p, sizeof (uwa_dir_config_rec));

  PRINTF("<create_uwa_dir_config>\n");
  uwa_crypt_seed();
  ua->active = 0;
  ua->partial = 0;
  ua->auth = NULL;
  ua->sp = p;
  ua->implor = -1;
  return ua;
}

/* Verbose display of auth config */
static int show_auth_set(uwa_dir_config_rec *dir_conf)
{
#if defined(UWA_LDAP_DEBUG_LEVEL)
   AuthSet a;
   AuthTok l;
   if (!dir_conf) {
      printf(" << no auth set >>\n");
      return;
   }
   if (!(a=dir_conf->auth)) {
      printf(" << empty auth set >>\n");
      return;
   }
   printf(" << auth set >> dir_conf=%x\n", dir_conf);
   printf(" << auth set >> a=%x\n", a);
   /* printf(" << auth set >> hash = %ld\n", a->hash); */
   while (a) {
      for (l=a->toks; l; l=l->next) printf("   | %d  %s\n", l->tok, l->text);
      a = a->next;
   }
#endif
}

/* Dir merge:  accumulate in 'AND' mode; only keep new in 'OR' mode */

static void *merge_uwa_dir_config (pool *p, void *basev, void *supplv)
{
  uwa_dir_config_rec *new = (uwa_dir_config_rec *)
      ap_pcalloc (p, sizeof (uwa_dir_config_rec));
  uwa_dir_config_rec *rec[2];
  uwa_dir_config_rec *base = (uwa_dir_config_rec *) basev;
  uwa_dir_config_rec *suppl = (uwa_dir_config_rec *) supplv;
  AuthSet *np,o;
  int i;

  PRINTF("<merge_uwa_dir_config>\n");

  rec[0] = (uwa_dir_config_rec *) basev;
  rec[1] = (uwa_dir_config_rec *) supplv;

  new->active = 0;
  new->partial = 0;
  new->auth = NULL;
  new->sp = p;
  new->implor = rec[rec[1]->implor!=-1]->implor;
  PRINTF("  implor=%d\n",new->implor);

#if defined(UWA_LDAP_DEBUG_LEVEL)
     printf("\n  base = \n");
     show_auth_set(rec[0]);
     printf("\n  suppl = \n");
     show_auth_set(rec[1]);
     if (new->implor>0) PRINTF("\n  .. not inheriting require lines\n");
#endif

  np = &new->auth;
  for (i=0;i<2;i++) {
    if (new->implor>0 && !i) continue; /* drop old if 'OR' */
    if (rec[i]->partial) new->partial = 1;
    if (rec[i]->active==0) {
       if (new->implor>0 && rec[i]->partial) new->active = 0;
       continue;
    }
    new->active = 1;

    for (o=rec[i]->auth;o;o=o->next) {
       AuthSet n = (AuthSet) ap_pcalloc (new->sp, sizeof (AuthSet_));
       AuthTok l,*qp;
       n->next = NULL;
       n->hash = o->hash;
       qp = &n->toks;
       for (l=o->toks;l;l=l->next) {
          AuthTok q = (AuthTok) ap_pcalloc (new->sp, sizeof (AuthTok_));
          q->next = NULL;
          q->tok = l->tok;
          if (l->text) q->text = ap_pstrdup(new->sp, l->text);
          else q->text = NULL;
          *qp = q;
          qp = &q->next;
       }
       *np = n;
       np=&n->next;
    }
  }

  return new;
}


/* UWAuth authtypes for activation.  */

const char *activate_uwa_dir_config (cmd_parms *cmd,
      void *dir_confv, const char *arg)
{
  uwa_dir_config_rec *dir_conf = (uwa_dir_config_rec*) dir_confv;
  PRINTF("<activate_uwa_dir_config>\n");
  if (!strcasecmp(arg,"UWNetID")) dir_conf->active = 1;
  else if (!strcasecmp(arg,"SecurID"))  dir_conf->active = 1;
  else if (!strcasecmp(arg,"shibboleth"))  dir_conf->active = 1;
  PRINTF("   UW authorize %sactivated by %s\n", dir_conf->active?"":"not ", arg);
  return DECLINE_CMD;
}

const char *de_activate_uwa_dir_config (cmd_parms *cmd,
      void *dir_confv, const char *arg)
{
  uwa_dir_config_rec *dir_conf = (uwa_dir_config_rec*) dir_confv;
  PRINTF("<de_activate_uwa_dir_config>\n");
  dir_conf->active = 0;
  dir_conf->partial = 1;
  PRINTF("   UW authorize de-activated by AuthGroupFile directive\n");
  return DECLINE_CMD;
}

const char *set_uwa_implicit_or (cmd_parms *cmd,
        void *dir_confv, int flag)
{
  uwa_dir_config_rec *dir_conf = (uwa_dir_config_rec*) dir_confv;
  dir_conf->implor = flag;
  return NULL;
}

const char *set_uwa_req_course_owner (cmd_parms *cmd,
        void *dir_confv, int flag)
{
  void *server_conf = cmd->server->module_config;
  uwa_config_rec *ua = (uwa_config_rec *)
        ap_get_module_config(server_conf, &uwa_module);

  ua->crsown = flag;
  return NULL;
}



/* ---  Read and tokenize a require command (dir config) -------------- */

static AuthTok addtok(pool *p, AuthTok *root, int tok, char *text)
{
   AuthTok n = (AuthTok) ap_pcalloc (p, sizeof (AuthTok_));
   n->next = NULL;
   n->tok = tok;
   n->text = text;
   (*root)->next = n;
   *root = n;
   return (n);
}

const char *set_uwa_dir_config (cmd_parms *cmd,
      void *dir_confv, const char *arg)
{
    void *server_conf = cmd->server->module_config;

    uwa_config_rec *ua = (uwa_config_rec *) 
                ap_get_module_config (server_conf, &uwa_module);  
    uwa_dir_config_rec *dir_conf = (uwa_dir_config_rec*) dir_confv;
    char *w;
    AuthSet a,b;
    AuthTok t,*tp;
    char *ln;
    int lastop = 0;
    int hk;

    PRINTF("<set_uwa_dir_config> \n");
    if (!dir_conf->active) {
       PRINTF("  not active \n");
       return DECLINE_CMD;
    }
    PRINTF("  cmd->path = %s \n", cmd->path?cmd->path:"NULL");
    PRINTF("  svr->path = %s \n", cmd->server->path);

    a = (AuthSet) ap_pcalloc (dir_conf->sp, sizeof (AuthSet_));
    a->next = NULL;
    a->hash = 0;
       
    t = (AuthTok) ap_pcalloc (dir_conf->sp, sizeof (AuthTok_));
    t->next = NULL;
    t->tok = AT_ROOT;;
    t->text = NULL;
    a->toks = t;
    tp = &t;

    /* get the list of users/groups/whatever */

#define IFW(m) if (!strcasecmp(w,m))

    hk = 1;
    while ((w=ap_getword_conf(cmd->pool, &arg))&&*w) {
       int argtok = 0;
       int tok = 0;

       PRINTF("  tok = %s \n", w);
       IFW("(") tok = AT_LP, NULL;
       else IFW(")") tok = AT_RP;
       else IFW("&") tok = AT_AND;
       else IFW("and") tok = AT_AND;
       else IFW("|") tok = AT_OR;
       else IFW("or") tok = AT_OR;
       else IFW("~") tok = AT_NOT;
       else IFW("not") tok = AT_NOT;
       else IFW("id") argtok = AT_ID;
       else IFW("user") argtok = AT_ID;
       else IFW("type") argtok = AT_TYPE;
       else IFW("group") argtok = AT_GROUP;
       else IFW("ugroup") argtok = AT_UGROUP;
       else IFW("course") argtok = AT_COURSE;
       else IFW("valid-user")  tok = AT_VALID;
       else if (lastop) argtok = 0 - lastop;
/**
       else return ("auth: syntax");
 **/
       else { /* not for us? */
           dir_conf->active = 0;
           dir_conf->partial = 1;
           PRINTF("   UW authorize de-activated by unknown require directive\n");
           return DECLINE_CMD;
       }

       if (tok) {
          addtok(dir_conf->sp, &t, tok, NULL);
          HASH(a->hash,tok,hk);
       } else if (argtok) {
          char *text;
          if (argtok>0) text = ap_getword_conf(dir_conf->sp, &arg);
          else {
             text = ap_pstrdup(dir_conf->sp, w);
             argtok = 0 - argtok;
          }
          PRINTF("  arg = %s \n", text);
          if (!*text) return ("auth: no value");
          addtok(dir_conf->sp, &t, argtok, text);
          lastop = argtok;
          HASH(a->hash,argtok,hk);
          for (w=text;*w;w++) HASH(a->hash,*w,hk);
       } else return ("authorization syntax");
    }

    /* link the new directive */
    if (a->toks->next) {
       if (!(b=dir_conf->auth)) dir_conf->auth = a;
       else {
          while (b->next) b = b->next;
          b->next = a;
       }
       show_auth_set(dir_conf);
    }

    return DECLINE_CMD;  /* allow core to record this also */

}


/* Output filter tools */

#ifdef UWA_DEFERRED_HEADERS

static void set_output_filter(request_rec *r)
{
   PRINTF("uwa adding output filter\n");
   ap_add_output_filter("UWA_HEADERS_OUT", NULL, r, r->connection);
}

static apr_status_t do_output_filter(ap_filter_t *f,
                                             apr_bucket_brigade *in)
{
    request_rec *r = f->r;
    uwa_request_rec *rr = (uwa_request_rec *) ap_get_module_config (r->request_config,
                                                     &uwa_module);

    if ( rr ) {
        ap_log_rerror (MY_LOG_DEBUG, r, "uwa output_filter: merging %d output headers",
                   apr_table_elts(rr->headers_out)->nelts);
        append_to_table(r, r->headers_out, rr->headers_out);
    }

    /* remove ourselves from the filter chain */
    ap_remove_output_filter(f);

    /* send the data up the stack */
    return ap_pass_brigade(f->next,in);
}
#endif /* UWA_DEFERRED_HEADERS */



/* Check authorization */

static char *strip_user(char *u)
{
   char *ret;
   char *p;
   
   if (!u) return (NULL);

   ret = strdup(u);
   if (p=strstr(ret,UWA_EPPN_DEFAULT)) *p = '\0';
   return (ret);
}
      

int 
uwa_set_cookie (request_rec *r, u_long data[MAX_CACHE], int ndata)
{
  void *server_conf = r->server->module_config;

  uwa_config_rec *ua = (uwa_config_rec *)
                ap_get_module_config (server_conf, &uwa_module);

#ifdef UWA_DEFERRED_HEADERS
  uwa_request_rec *rr = (uwa_request_rec*)  ap_get_module_config (r->request_config,
                                               &uwa_module);
  if (!rr) return (0);
#endif

  char ctext[MAX_CACHEB], etext[MAX_CACHEB];
  int ctextl, etextl;
  unsigned char *e, *v;
  time_t t = time(NULL);
  char ck[1024];
  int i;
  int h,l;
  char *ruser = strip_user(r->USER);

   ctextl = 4 + MAX_ID + sizeof(time_t);
   memset(ctext, 0, ctextl);
   strcpy(ctext, "UWA ");
   strcpy(ctext+4, ruser);
   t += TIMEOUT_TIME;
   memcpy(ctext+4+MAX_ID, &t, sizeof(time_t));
   PRINTF("uwa: set cookie, user=%s, to=%d\n", ctext, t += TIMEOUT_TIME);
   for (i=0;i<ndata;i++) {
       PRINTF("  adding hash = %d\n",data[i]);
       memcpy(ctext+ctextl,&data[i],sizeof(u_long));
       ctextl += sizeof(u_long);
   }
   PRINTF("  len = %d\n", ctextl);
   uwa_crypt(UWA_ENCRYPT, etext, &etextl, ctext, ctextl);

   for (i=0,e=(unsigned char*)etext,v=(unsigned char*)ctext;i<etextl;i++,e++) {
      int h = *e/16;
      int l = *e - h*16;
      *v++ = h+'a';
      *v++ = l+'a';
   }
   *v = '\0';

     PRINTF("uwa: enc = %s\n", ctext);

     sprintf(ck, "%s=%s; path=/; secure", ua->cookie, ctext);
     PRINTF("  set-cookie: %s\n", ck);
#ifdef UWA_DEFERRED_HEADERS
     ap_table_add(rr->headers_out, "Set-Cookie", ck);
#else
     ap_table_add(r->headers_out, "Set-Cookie", ck);
#endif
}

int uwa_get_cookie (request_rec *r, u_long *data, int *ldata)
{
  void *server_conf = r->server->module_config;

  uwa_config_rec *uwa = (uwa_config_rec *)
                ap_get_module_config (server_conf, &uwa_module);

  uwa_dir_config_rec *uirwad = (uwa_dir_config_rec *)
                ap_get_module_config (r->per_dir_config, &uwa_module);


  conn_rec *c = r->connection;

  char *ck, *ckp;
  char *value;
  char etext[MAX_CACHEB];
  int ctextl, etextl;
  int l;
  char *e, *v;
  time_t ct;
  time_t nt = time(NULL);
  char ctext[MAX_CACHEB];
  char *ruser = strip_user(r->USER);

  /* Skip if not configured */

  *ldata = 0;
  if (!(uwa->enabled)) return 0;

  PRINTF("uwa: cookie check\n");

  /* Look for the login cookie */

  if (!(ckp=(char*)ap_table_get (r->headers_in, "Cookie"))) return 0;

  /* search the cookies */
  if (!(ck = ap_palloc (r->pool, 2 + strlen (ckp)))) {
      ap_log_rerror(MY_LOG_ERR, r, "mod_uwa: palloc failed!");
      return 0;
  };
  strcpy (ck, ckp);
  ck[0 + strlen (ckp)] = ';';
  ck[1 + strlen (ckp)] = '\0';

  /* note that there could be bogus cookies, set by miscreants */
  for (ck=strtok (ck," ;\n\r\t\f"); ck; ck=strtok (NULL, " ;\n\r\t\f")) {

      if (!ck) break;
      if (!(value = strchr (ck,'='))) continue;

      *value = '\0';
      value++;

      if (strcmp(ck, uwa->cookie)) continue;

      /* value is encrypted userid */

      PRINTF("uwa: ck val = %s\n", value);
      etextl = strlen(value);
      if (etextl != ((etextl/2)*2)) {
         PRINTF("uwa: bogus cookie: odd length\n");
         continue;
      } 
      for (etextl=0,v=value,e=etext;*v&&etextl<MAX_CACHEB;etextl++) {
          *e = (*v++ - 'a') * 16;
          *e++ += (*v++ - 'a');
      }
      if (etextl==MAX_CACHEB) {
         PRINTF("uwa: bogus cookie: >%d\n", MAX_CACHEB);
         continue;
      }
      *e = '\0';
         
      uwa_crypt(UWA_DECRYPT, ctext, &ctextl, etext, etextl);


      if (strncmp(ctext,"UWA",3)) {
         PRINTF("uwa: bogus cookie: not UWA, e=%d, c=%d\n", etextl, ctextl);
         continue;
      }

      memcpy(&ct, ctext+4+MAX_ID, sizeof(time_t));
      if (nt>ct) {
         PRINTF("uwa: cookie expired=%d>%d\n", nt, ct);
      } else if (strncmp(ctext+4,ruser, strlen(ruser))) {
         PRINTF("uwa: cookie wrong user=%s/%s\n", ctext+4, ruser);
      } else {
         char *p;
         int i;
         PRINTF("uwa: cookie OK=%s\n", ctext);
         p = ctext + 4 + MAX_ID + sizeof(time_t);
         while (p<ctext+ctextl && (*ldata)<MAX_CACHE) {
            memcpy(data,p,sizeof(u_long));
            PRINTF("  extracted hash = %d\n", *data);
            data++;
            p += sizeof(u_long);
            (*ldata)++;
         }
         return 1;
      }
      return (0);
  }

  return 0;
}


/* auth eval tokens */

typedef struct AuthEv__ {
  struct AuthEv__ *next;
  struct AuthEv__ *prev;
  int tok;
  int value;
  int level;
} AuthEv_, *AuthEv;

typedef struct AuthEvStack__ {
  int level;
  AuthEv start;
  AuthEv end;
  pool *p;
} AuthEvStack_, *AuthEvStack;

/* push something */
static void epush(AuthEvStack stk, int tok, int value)
{
   AuthEv ev;

   if (stk->end->next) ev = stk->end->next;
   else {
      ev = (AuthEv) ap_pcalloc(stk->p, sizeof(AuthEv_));
      ev->next = NULL;
      ev->prev = stk->end;
      stk->end->next = ev;
   }
   ev->tok = tok;
   ev->value = value;
   ev->level = stk->level;
   stk->end = ev;
   PRINTF("   push %d, %d\n", ev->tok, ev->value); 
}
 
static void epull(AuthEvStack stk, AuthEv *ev)
{
   AuthEv s;
   AuthEv e;
   *ev = e = stk->end;
   for (s=stk->start;s&&s->next!=*ev;s=s->next);
   stk->end = s;
   if (e) PRINTF("   pull %d, %d\n", e->tok, e->value); 
}

   
/* push a value - maybe do operation too */
static void epushv(AuthEvStack stk, int value)
{
   AuthEv e;

   if (stk->end->level!=stk->level) {
      epush(stk, AT_VALUE, value);
      return;
   }

   if (stk->end->tok==AT_NOT) {
      epull(stk, &e);
      epush(stk, AT_VALUE, !value);
   } else if (stk->end->tok==AT_OR) {
      epull(stk, &e);
      epull(stk, &e);
      epush(stk, AT_VALUE, value||e->value);
   } else if (stk->end->tok==AT_AND) {
      epull(stk, &e);
      epull(stk, &e);
      epush(stk, AT_VALUE, value&&e->value);
   } else if (stk->end->tok==AT_VALUE) { /* assume 'or' */
      PRINTF(" >> assuming OR operation: \n");
      epull(stk, &e);
      epush(stk, AT_VALUE, value||e->value);
   } else epush(stk, AT_VALUE, value);
}


static int 
uwa_authorize (request_rec * r)
{
  void *server_conf = r->server->module_config;

  uwa_config_rec *uwa = (uwa_config_rec *)
                ap_get_module_config (server_conf, &uwa_module);

  uwa_dir_config_rec *uwadir = (uwa_dir_config_rec *)
                ap_get_module_config (r->per_dir_config, &uwa_module);

  uwa_request_rec *rr = (uwa_request_rec *) ap_get_module_config (r->request_config,
                                                     &uwa_module);

  char *ck, *ckp;
  char *ctext;
  char *cuser;
  AuthSet auth;
  char *grptext;
  int newhash = 0;
  void *type_list = NULL;

  struct group *grp;
  char **gent;
  gid_t gid;
  int n;
  int implor = uwadir->implor == -1 ? 0 : uwadir->implor;
  int implorok = 0;
  u_long *uhash;  /* list of hashes */
  int *nuhash = NULL; /* number of hashes */

  AuthEvStack_ evstack_;
  AuthEv_ rootev_;

  char *ruser = strip_user(r->USER);

  /* Skip if not configured */

  ap_log_rerror(MY_LOG_DEBUG, r, "uwa: enter, %d, %d, %d, %s(%s)\n",
         uwa->enabled, uwadir->active, uwadir->auth, ruser, r->USER);

  if (!(uwa->enabled && uwadir->active && uwadir->auth && ruser)) {
      return DECLINED;
  }

  ap_log_rerror(MY_LOG_DEBUG, r, "uwa: active, user=%s\n", ruser);

  evstack_.level = 0;
  evstack_.start = &rootev_;
  evstack_.end = &rootev_;
  evstack_.p = r->pool;
  rootev_.next = NULL;
  rootev_.prev = NULL;
  rootev_.tok = AT_ROOT;
  rootev_.value = 0;
  rootev_.level = 0;

  /* Look for cached auths (cookie or parent) */

  if (r->main) {
     uwa_request_rec *prr = (uwa_request_rec *) ap_get_module_config (r->main->request_config,
                                                     &uwa_module);
     if (prr) {
        uhash = prr->uhash;
        nuhash = &prr->nuhash;
     } else if (rr) {
        uhash = rr->uhash;
        nuhash = &rr->nuhash;
     }
  } else if (rr) {
     uwa_get_cookie(r, rr->uhash, &rr->nuhash);
     uhash = rr->uhash;
     nuhash = &rr->nuhash;
  }
     
  /* check authorization - one for each 'require' line */

  ap_log_rerror(MY_LOG_DEBUG, r, "uwa: checking authorizations, %d cached%s\n", nuhash?*nuhash:0, r->main?"(sub)":"");
  
  for (auth=uwadir->auth;auth;auth=auth->next) {
     int u;
     AuthTok t;
     AuthEvStack evstack = &evstack_;
     AuthEv ev;
     int v = 0;
     int v1 = 0;
     unsigned long ut;
     char sn[16];
     struct passwd *pwe;
     int uid;

     ap_log_rerror(MY_LOG_DEBUG, r, "uwa chk: hash = %d\n", auth->hash);
     
     /* check the cache of recent authorizations */
     for (u=0;nuhash&&u<*nuhash;u++) {
         if (uhash[u] == auth->hash) {
            ap_log_rerror(MY_LOG_DEBUG, r, " .. found by hash cache\n");
            v = 1;
            break;
         }
     }
     if (v) {
        if (!implor) continue;
        implorok = 1;
        break;
     }

     /* Determine truth value of the require line */

     for (t=auth->toks; t; t=t->next) {
       PRINTF("  tok=%d, l = %d\n", t->tok, evstack->level);
       switch (t->tok) {

         case AT_ID:
            v = !strcmp(t->text,ruser);
            if (!v) v = !strcmp(t->text,r->USER);
            epushv(evstack, v);
            break;

         case AT_TYPE:
            if (!connect_to_ldap(r, uwa->cfg[PR_LDAP])) return HTTP_INTERNAL_SERVER_ERROR;
            if (!type_list) type_list = uw_auth_get_types(uwa->cfg[PR_LDAP], ruser);
            v = uw_auth_chk_type(type_list, t->text);
            ap_log_rerror(MY_LOG_DEBUG, r, "  auth type %s = %d\n", t->text, v);
            epushv(evstack, v);
            break;

         case AT_GROUP:
            if (!connect_to_ldap(r, uwa->cfg[GR_LDAP])) return HTTP_INTERNAL_SERVER_ERROR;
            v = uw_auth_chk_in_group(uwa->cfg[GR_LDAP], ruser, t->text);
            ap_log_rerror(MY_LOG_DEBUG, r, "  auth group %s = %d\n", t->text, v);
            epushv(evstack, v);
            break;

         case AT_COURSE:
            if (uwa->crsown) {
#ifdef APACHE2
               uid = r->finfo.user;
#else
               uid = r->finfo.st_uid;
#endif
               pwe = getpwuid(uid);
               ap_log_rerror(MY_LOG_DEBUG, r, "course check: uid=%d, id=%s", uid, pwe?pwe->pw_name:"-not found-");
               if (!pwe) {
                  ap_log_rerror(MY_LOG_ERR, r, "course check: no userid"); 
                  return HTTP_INTERNAL_SERVER_ERROR;
               }
            } else pwe = NULL;
            if (!connect_to_ldap(r, uwa->cfg[CR_LDAP])) return HTTP_INTERNAL_SERVER_ERROR;
            v = uw_auth_chk_in_course(uwa->cfg[CR_LDAP], ruser, t->text, pwe?pwe->pw_name:NULL);
            if (v<0) {
               ap_log_rerror(MY_LOG_ERR, r, "course check: no permission to %s", t->text); 
               return HTTP_INTERNAL_SERVER_ERROR;
            }
            ap_log_rerror(MY_LOG_DEBUG, r, "  auth course %s = %d\n", t->text, v);
            epushv(evstack, v);
            break;

         case AT_UGROUP:
            if (! (grp = getgrnam (t->text))) {
                ap_table_setn(r->notes, "error-notes", "group not found\n");
                ap_log_rerror(MY_LOG_ERR, r,
                                "group %s not found", t->text);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            setgrent ();
            gid = grp->gr_gid;
            ap_log_rerror(MY_LOG_DEBUG, r,
                            "gid=%d user=%s", gid, ruser);
            while (grp = getgrent ()) {
                if (gid != grp->gr_gid)
                    continue;
                ap_log_rerror(MY_LOG_DEBUG, r,
                                "checking %s", grp->gr_name);
                for (gent = grp->gr_mem; *gent && **gent; ++gent)
                    if (! strcmp (r->USER, *gent)) {
                        ap_log_rerror(MY_LOG_DEBUG, r, "got it");
                        v = 1;
                        break;
                    }
                if (v) break;
            }
            endgrent ();
            epushv(evstack, v);
            break;

         case AT_VALID:
            epushv(evstack, 1);
            break;

         case AT_AND:
         case AT_OR:
         case AT_NOT:
            epush(evstack, t->tok, 0);
            break;
         case AT_LP:
            evstack->level++;
            break;
         case AT_RP:
            evstack->level--;
            epull(evstack, &ev);
            epushv(evstack, ev->value);
            break;
         case AT_ROOT:
            break;
         default:
            return HTTP_INTERNAL_SERVER_ERROR;
         
       }
     }
     epull(evstack, &ev);
     if (ev->tok!=AT_VALUE) return HTTP_INTERNAL_SERVER_ERROR;
     v = ev->value;
     PRINTF("    val: %d\n", v);

     /* Act upon the value */ 

     if (!v) {
        if (implor) continue;  /* 'OR' gets more chances */

        ap_log_rerror(MY_LOG_DEBUG, r, "   REJECT by require\n");
        ap_table_setn(r->notes, "error-notes",
                          "Rejected by UW authorization directive\n");
        return HTTP_UNAUTHORIZED;
     }

     PRINTF("   ok so far\n");
     if (nuhash) {
        if (*nuhash>MAX_CACHE-2) {
           *nuhash=0; /* dont know what to do - just clear and start over */
        }
        uhash[*nuhash] = auth->hash;
        *nuhash += 1;
        newhash++;
     }
     
     if (implor) {
        implorok = 1;
        ap_log_rerror(MY_LOG_DEBUG, r, "  Dropping through with implicit OR\n");
        break;
     }

  }

  /* If implicit OR and not found anything, error */
  if (implor && ! implorok) {
     ap_log_rerror(MY_LOG_DEBUG, r, "   REJECT by require\n");
     ap_table_setn(r->notes, "error-notes", "Rejected by UW authorization directive\n");
     return HTTP_UNAUTHORIZED;
  }

  /* OK, got through all the requires */

  ap_log_rerror(MY_LOG_DEBUG, r, " .. uwauth OK\n");

  if (newhash && !r->main) uwa_set_cookie(r, uhash, *nuhash);

  if (uwadir->partial) {
      ap_log_rerror(MY_LOG_DEBUG, r, " .. allowing further authorization checks\n");
      return DECLINED;
  }
  return OK;
}



/* ------  Configuration ---------- */

#ifdef APACHE1_3
#define AP_INIT_TAKE1(d,f,c,w,h) { d,f,c,w,TAKE1,h}
#define AP_INIT_NO_ARGS(d,f,c,w,h) { d,f,c,w,NO_ARGS,h}
#define AP_INIT_RAW_ARGS(d,f,c,w,h) { d,f,c,w,RAW_ARGS,h}
#define AP_INIT_ITERATE(d,f,c,w,h) { d,f,c,w,ITERATE,h}
#define AP_INIT_FLAG(d,f,c,w,h) { d,f,c,w,FLAG,h}
#define AP_INIT_ITERATE2(d,f,c,w,h) { d,f,c,w,ITERATE2,h}
#endif


static const command_rec uwa_cmds[] =
{
  /* server directives */
  AP_INIT_NO_ARGS("UWAuth",
      set_uwa_active, NULL, RSRC_CONF,
     "[activates module]"
  ),
     
  AP_INIT_TAKE1("UWAuthLdapServer",
      set_uwa_ldapserver, NULL, RSRC_CONF,
     "ldapserver:port"
  ),
     
  AP_INIT_TAKE1("UWAuthPersonLdapServer",
      set_uwa_pr_ldapserver, NULL, RSRC_CONF,
     "ldapserver:port"
  ),
     
  AP_INIT_TAKE1("UWAuthGroupLdapServer",
      set_uwa_gr_ldapserver, NULL, RSRC_CONF,
     "ldapserver:port"
  ),
     
#ifdef CR_LDAP
  AP_INIT_TAKE1("UWAuthCourseLdapServer",
      set_uwa_cr_ldapserver, NULL, RSRC_CONF,
     "ldapserver:port"
  ),
#endif
     
  AP_INIT_TAKE1("UWAuthBindInfo",
      set_uwa_bindinfo, NULL, RSRC_CONF,
     "bind info file"
  ),
     
  AP_INIT_NO_ARGS("UWAuthK5",
      set_uwa_k5, NULL, RSRC_CONF,
     "use ticket cache for auth"
  ),
     
  AP_INIT_TAKE1("UWAuthCertDB",
      set_uwa_certdb, NULL, RSRC_CONF,
     "cert db file"
  ),
     
  AP_INIT_TAKE1("UWAuthBindCert",
      set_uwa_bindcrt, NULL, RSRC_CONF,
     "bind cert file"
  ),
     
  AP_INIT_TAKE1("UWAuthBindKey",
      set_uwa_bindkey, NULL, RSRC_CONF,
     "bind key file"
  ),
     
  AP_INIT_TAKE1("UWAuthCookie",
      set_uwa_cookie, NULL, RSRC_CONF,
     "cookie_name"
  ),
     
  AP_INIT_FLAG("UWAuthRequireCourseOwnership",
      set_uwa_req_course_owner, NULL, RSRC_CONF,
     "courses must be owned by web page owner"
  ),
  /* 
  AP_INIT_NO_ARGS("UWAuthNoSSL",
      set_uwa_nossl, NULL, RSRC_CONF,
     "ssl not needed"
  ),
     
    */
  /* directory directives */
  AP_INIT_RAW_ARGS("require",
      set_uwa_dir_config, NULL, OR_AUTHCFG,
     "UW Authorization requirements"
  ),
     
  AP_INIT_TAKE1("AuthType",
      activate_uwa_dir_config, NULL, OR_AUTHCFG,
     "Authorization type"
  ),
     
  AP_INIT_RAW_ARGS("AuthGroupFile",
      de_activate_uwa_dir_config, NULL, OR_AUTHCFG,
     "group file"
  ),
     
  AP_INIT_FLAG("UWAuthImplicitOr",
     set_uwa_implicit_or, NULL, OR_AUTHCFG,
    "multiple require lines OR instead of AND; implies no inheriting requires"
  ),
     
  {NULL}
};

#ifdef APACHE1_3

module uwa_module = {
  STANDARD_MODULE_STUFF,
  uwa_init,			/* initializer */
  create_uwa_dir_config,   	/* dir config creater */
  merge_uwa_dir_config,		/* dir merger */
  create_uwa_config,		/* server config */
  NULL,				/* merge server configs */
  uwa_cmds,			/* command table */
  NULL,				/* handlers */
  NULL,				/* filename translation */
  NULL,				/* check_user_id */
  uwa_authorize,		/* check auth */
  NULL,				/* check access */
  NULL,				/* type_checker */
  uwa_fixups,			/* fixups */
  NULL,				/* logger */
  NULL,                         /* [3] header parser */
  NULL,                         /* process initializer */
  NULL,                         /* process exit/cleanup */
  uwa_post_read                 /* [1] post read_request handling */
};

#else /* apache 2.x */

static void register_hooks(pool *p) {
#ifdef UWA_DEFERRED_HEADERS
    ap_register_output_filter("UWA_HEADERS_OUT", do_output_filter,
                              NULL, AP_FTYPE_CONTENT_SET);
    ap_hook_insert_filter(set_output_filter, NULL, NULL, APR_HOOK_LAST);
#endif

    ap_hook_post_config(uwa_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_auth_checker(uwa_authorize, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_post_read_request (uwa_post_read, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups (uwa_fixups, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_pre_config (uwa_pre_config, NULL, NULL, APR_HOOK_MIDDLE);

}
module AP_MODULE_DECLARE_DATA uwa_module = {
    STANDARD20_MODULE_STUFF,
    create_uwa_dir_config,
    merge_uwa_dir_config,
    create_uwa_config,
    NULL,   /* merge_uwa_config, */
    uwa_cmds,
    register_hooks,
};
#endif /* apache */




