/* mod_uwa ldap tools */


#include "config.h"

/* These printf only useful for debugging with httpd run with -X */
#if defined(MOD_UWA_DEBUG)
#define PRINTF if (1) printf
#else 
#define PRINTF if (0) printf
#endif

#define LDAP_DEPRECATED 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


#include <ldap.h>
#include <lber.h>
#include <sasl/sasl.h>

#include "httpd.h"
#include "http_log.h"
#ifdef APACHE2
#define MY_LOG_DEBUG APLOG_MARK,APLOG_DEBUG,0
#define MY_LOG_INFO  APLOG_MARK,APLOG_INFO,0
#define MY_LOG_ERR   APLOG_MARK,APLOG_ERR,0
#else /* apache 1.3 */
#define MY_LOG_DEBUG APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO
#define MY_LOG_INFO  APLOG_MARK,APLOG_INFO|APLOG_NOERRNO
#define MY_LOG_ERR   APLOG_MARK,APLOG_ERR
#endif

#include "ldaplib.h"

static int chk_in_group(LDAP *ld, LdapConfig *cfg, char *group, char *um, int dpth);
static int chk_in_crs_group(LDAP *ld, LdapConfig *cfg, char *base, char *sln,
    char *um, char *atr1, char *atr2, char *atr3);
static int get_attr_for_id(LDAP *ld, LdapConfig *cfg, char *cn, char *attr, char ***values);


/* ----- tools -----------*/

/* malloc and copy a string, l is strlen */
static char *newstr(char *src, int l)
{
   char *s = (char*) malloc(l+1);
   strncpy(s,src,l);
   s[l] = '\0';
   return (s);
}


/* A host name, e.g. author.u.washington.edu, may actually be
   the name of a cluster.  We want the individual hosts returned
   for that cluster.  For simple auth it is just convenient;
   for kerberos auth it is necessary. 

   In addition, we allow the ldap library convention that a 
   list of hosts may be submitted by separating the names
   with spaces. */

#define MAX_LDAP_HOSTS 10  /* much more than needed? */
static int get_hosts(char **hosts, char *hostnames, int *hl, int *ht)
{
    struct hostent *ldh;
    int h;
    int nh = 0;
    char **hp;
    char *host;
    char *p;
       
    for (;;) {
       while (*hostnames && isspace(*hostnames)) hostnames++;
       if (!*hostnames) break;
       for (p=hostnames;*p && !isspace(*p); p++);
       host = newstr(hostnames, p-hostnames);

       /* get the host, may be a list */

       ldh = gethostbyname(host);
       if (!ldh) {
          perror("gethostbyname");
          continue;
       }
       *hl = ldh->h_length;
       *ht = ldh->h_addrtype;
       for (hp=ldh->h_addr_list;*hp && nh<MAX_LDAP_HOSTS;nh++,hp++) {
          char *hx = (char *)malloc(*hl);
          memcpy(hx,*hp,*hl);
          hosts[nh] = hx;
       }
       hostnames = p;
    }
    return (nh);
}
        
static void set_ldap_debug()
{
#if defined(UWA_LDAP_DEBUG_LEVEL)
  int debug = UWA_LDAP_DEBUG_LEVEL;
  if( ber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &debug )
          != LBER_OPT_SUCCESS ) {
      fprintf( stderr, "Could not set LBER_OPT_DEBUG_LEVEL %d\n", debug );
  }
  if( ldap_set_option( NULL, LDAP_OPT_DEBUG_LEVEL, &debug )
         != LDAP_OPT_SUCCESS ) {
      fprintf( stderr, "Could not set LDAP_OPT_DEBUG_LEVEL %d\n", debug );
  }
#endif /* debug */
}

void show_cfg(LdapConfig *cfg)
{
#if defined(UWA_LDAP_DEBUG_LEVEL)
   PRINTF("LdapConfig: host=%s:%d\n", cfg->host, cfg->port);
   if (cfg->binddn) PRINTF("     binddn=%s, bindpw=%s\n", cfg->binddn, cfg->bindpw);
   if (cfg->certdb) PRINTF("     certdb=%s\n", cfg->certdb);
   if (cfg->bindcrt) PRINTF("     bindcrt=%s, key=%s\n", cfg->bindcrt, cfg->bindkey);
#endif /* debug */
}

/* New config struct, load with defaults */

LdapConfig *new_ldap_cfg()
{
   LdapConfig *cfg = (LdapConfig*) malloc(sizeof(LdapConfig));

   memset(cfg, '\0', sizeof(LdapConfig));
   cfg->host = UWA_LDAP_HOST;
   cfg->port = UWA_LDAP_PORT;
/***
   cfg->sslport = UWA_LDAP_SSL_PORT;

   cfg->usr_base = UWA_LDAP_USR_BASE;
   cfg->usr_typattr = UWA_LDAP_TYPATTR;

   cfg->gr_base = UWA_LDAP_GR_BASE;
   cfg->gr_mbrfmt = UWA_LDAP_GR_MBRFMT;
   cfg->gr_nameattr = UWA_LDAP_GR_NAMEATTR;
   cfg->gr_eppnfmt = UWA_LDAP_GR_EPPNFMT;
   cfg->gr_mbrattr = UWA_LDAP_GR_MBRATTR;
   cfg->gr_gmbrattr = UWA_LDAP_GR_GMBRATTR;
   cfg->gr_onrattr = UWA_LDAP_GR_ONRATTR;

   cfg->cr_base = UWA_LDAP_CR_BASE;
   cfg->cr_mbrfmt = UWA_LDAP_CR_MBRFMT;
   cfg->cr_nameattr = UWA_LDAP_CR_NAMEATTR;
   cfg->cr_stdattr = UWA_LDAP_CR_STDATTR;
   cfg->cr_insattr = UWA_LDAP_CR_INSATTR;
   cfg->cr_onrattr = UWA_LDAP_CR_ONRATTR;
 ***/
   return (cfg);
}

static int
tsasl_interact(LDAP *ld, unsigned flags, void *defaults, void *in)
{
        sasl_interact_t *interact = in;
        /* Should loop through, ++interact, for full SASL stuff. */
        if (interact->id != SASL_CB_LIST_END) {
                interact->result = (char *) interact->defresult;
                if (interact->defresult)
                        interact->len = strlen(interact->defresult);
                else
                        interact->len = 0;
        }
        return LDAP_SUCCESS;
}


/* ---- Public interfaces -------------------------------------- */


/* Connects to ldap and authenticates.
   Sets the LDAP pointer (opaque)
   Return true if connection OK 
   Does nothing if already connected
 */

int uw_auth_connect(LdapConfig *cfg, request_rec *r)
{
   
    LDAP *ld = NULL;
    LDAPMessage    *result, *e;
    int        i;
    struct hostent *ldh;
    char *host = NULL;
    char *hosts[MAX_LDAP_HOSTS];
    int h, nh;
    int hl, ht;
    char **hp;
    int protocol = LDAP_VERSION3;
    int port;


    ap_log_rerror (MY_LOG_DEBUG, r, "uw_auth_connect to %s\n", cfg->host);

    PRINTF( ".. uw_auth_connect to %s\n", cfg->host);

    /* show_cfg(cfg); */
    if (cfg->ldap) return (1); /* already connected */

    nh = get_hosts(hosts, cfg->host, &hl, &ht);
        
    /* Try the connection for each possible host */

    /* some of the initialize code could possibly be taken
       out of the loop, but I don't know the effect of the various
       connection errors on the initialized state.  So, I just
       reinitialize on each try.  It doesn't take long, and
       shouldn't happen often. */

    for (h=0; h<nh && !ld; h++) {

       ldh = gethostbyaddr(hosts[h], hl, ht);
       if (!ldh) continue;
       if (host) free (host);
       host = newstr(ldh->h_name, strlen(ldh->h_name));
       port = cfg->port;

    ap_log_rerror (MY_LOG_DEBUG, r, "trying connect to %s\n", host);
       PRINTF( "Trying %sconnect to %s\n",
            cfg->certdb?"SSL ":"",host);

       /* Get a handle to the server - tls or plain */

       if (cfg->certdb) {  /* tls version */
          int rc;

          set_ldap_debug();

          if ((ld=ldap_init(host, cfg->port))==NULL) {
              perror( "ldap_init" );
              continue;
          }

          rc = LDAP_VERSION3;
          if ( ldap_set_option( NULL, LDAP_OPT_PROTOCOL_VERSION, &rc ) != LDAP_SUCCESS ) {
              ldap_perror( ld, "ldap_set_option LDAPv3" );
              ld = NULL;
              continue;
          }

          rc = LDAP_OPT_X_TLS_DEMAND;
          if ( ldap_set_option( NULL, LDAP_OPT_X_TLS, &rc ) != LDAP_SUCCESS ) {
              ldap_perror( ld, "ldap_set_option LDAP_OPT_X_TLS" );
              ld = NULL;
              continue;
          }

          PRINTF("certdb = '%s'\n", cfg->certdb);
          if ( ldap_set_option( NULL, LDAP_OPT_X_TLS_CACERTFILE, cfg->certdb ) != LDAP_SUCCESS ) {
              ldap_perror( ld, "ldap_set_option cacert" );
              ld = NULL;
              continue;
          }

          PRINTF(".. ldap tls initialize ok\n");

       } else { /* not ssl */

          if ( (ld = ldap_init( cfg->host, cfg->port )) == NULL ) {
              perror( "ldap_init" );
              continue;
          }

       } 

       /* Choose bind method  */

       if (cfg->certdb && cfg->bindcrt) {
        
          /* cert */
          PRINTF("using cert from %s\n", cfg->bindcrt);
          if ( ldap_set_option( NULL, LDAP_OPT_X_TLS_CERTFILE, cfg->bindcrt ) < 0 ) {
              ldap_perror( ld, "ldap_set_option bindcrt" );
              ld = NULL;
              continue;
          }

          if ( ldap_set_option( NULL, LDAP_OPT_X_TLS_KEYFILE, cfg->bindkey ) < 0 ) {
              ldap_perror( ld, "ldap_set_option bindkey" );
              ld = NULL;
              continue;
          }

       /* use LDAPv3 */
       i = LDAP_VERSION3;
       if ( ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &i ) < 0 ) {
           ldap_perror( ld, "ldap_set_option LDAPv3" );
           ldap_unbind( ld );
           ld = NULL;
           continue;
       }

         if ( ldap_start_tls_s(ld, NULL,NULL) != LDAP_SUCCESS) {
             ldap_perror(ld, "ldap_start_tls_s");
             ld = NULL;
             continue;
          }

         if ( ldap_sasl_interactive_bind_s(ld, NULL, "EXTERNAL", 0, 0,
                LDAP_SASL_AUTOMATIC|LDAP_SASL_QUIET, tsasl_interact, 0) != LDAP_SUCCESS) {
             ldap_perror(ld, "ldap_sasl_interactive_bind_s");
             ld = NULL;
             continue;
          }


       } else if (cfg->gssapi) {
        
          /* has k5 ticket cache */
          const char *dn = "";
          const char *mech = "GSSAPI";
          PRINTF("using gssapi\n");
          if ( ldap_sasl_interactive_bind_s(ld, dn, mech, 0, 0,
                LDAP_SASL_AUTOMATIC|LDAP_SASL_QUIET, tsasl_interact, 0) != LDAP_SUCCESS) {
             ldap_perror(ld, "ldap_sasl_interactive_bind_s");
             ld = NULL;
             continue;
          }

       } else {

          /* user and password */
          PRINTF("using simple bind with pw for %s\n", cfg->binddn);
          if ((i=ldap_simple_bind_s(ld,cfg->binddn,cfg->bindpw))!=LDAP_SUCCESS) {
              ldap_perror( ld, "bind" );
              ld = NULL;
              continue;
          }
       }
       PRINTF(".. ldap start bind ok\n");

    }

    cfg->ldap = ld;
    if (ld) ap_log_rerror (MY_LOG_DEBUG, r, "ldap connect OK to %s (%s).\n", cfg->host, host);
    else ap_log_rerror (MY_LOG_DEBUG, r, "ldap connect failed to %s.\n", cfg->host);
    if (host) free(host);
    return (ld!=NULL);
}



/* ---- Exported group membership functions ----------------- */


/* Test if an id is in a group. 
   Returns 1 if in, 0 if not.

   If the group has members that are groups, they will be checked also.
 */

int uw_auth_chk_in_group(LdapConfig *cfg, char *id, char *group) 
{
    int ret;
    LDAP  *ld;
    char *um;  /* length = preface + id + base */

    // if (!cfg->ldap) uw_auth_connect(cfg);
    if (!(ld=(LDAP*)cfg->ldap)) return 0;

    /* make the um attribute value to find */

    if (strchr(id, '@')) {    /* eppn */
       um = (char*) malloc(strlen(UWA_LDAP_GR_EPPNFMT)+strlen(id)+8);
       sprintf(um, UWA_LDAP_GR_EPPNFMT, id);
    } else {                  /* uwnetid */
       um = (char*) malloc(strlen(UWA_LDAP_GR_MBRFMT)+strlen(id)+8);
       sprintf(um, UWA_LDAP_GR_MBRFMT, id);
    }
    ret = chk_in_group(ld, cfg, group, um, 0);
    free (um);
    return ret;
}
       
/* Test if a uwnetid is in a paticular class.
   class is "QQQYYYY.SLN" 

   In addition, we may require the owner of the resource ('owner') to be
   an instructor or owner of the class in order to use this procedure. 

   Return 1 if in course.
   Return 0 if not in course.
   Return -1 if no permission to course by page owner.
   */

int uw_auth_chk_in_course(LdapConfig *cfg, char *id, char *class, char *owner) 
{
   LDAP  *ld;
   char *um;
   int ret;
   char *base;
   char qtr[16];
   char sln[16];
   char *d;

   //  if (!cfg->ldap) uw_auth_connect(cfg);
    if (!(ld=(LDAP*)cfg->ldap)) return 0;

   if (strlen(class)>15) return (0);
   strncpy(qtr,class,15);
   d = strchr(qtr,'.');
   if (!d) return (0);
   *d++ = '\0';
   strncpy(sln,d,15);

   /* Check that the requestor is authorized for this class. */

   PRINTF("course_group: id=%s, course=%s, owner=%s\n", id, class, owner?owner:"-none-");
   base = (char*) malloc(strlen(UWA_LDAP_CR_BASE)+32);
   sprintf(base, "ou=%s,%s", qtr, UWA_LDAP_CR_BASE);

   if (owner) {
      um = (char*) malloc(strlen(UWA_LDAP_CR_MBRFMT)+strlen(owner)+8);
      sprintf(um, UWA_LDAP_CR_MBRFMT, owner);
   
      /* check the class group for 'instructor' or 'owner'  */

      ret = chk_in_crs_group(ld, cfg, base, sln, um, 
         UWA_LDAP_CR_INSATTR, UWA_LDAP_CR_ONRATTR, NULL);

      free(um);
      if (!ret) {
         PRINTF("course_group, requestor not owner\n");
         free(base);
         return (-1);
      }
   }

   um = (char*) malloc(strlen(UWA_LDAP_CR_MBRFMT)+strlen(id)+8);
   sprintf(um, UWA_LDAP_CR_MBRFMT, id);
   
   /* check the class list */

   ret = chk_in_crs_group(ld, cfg, base, sln, um, 
        UWA_LDAP_CR_STDATTR, UWA_LDAP_CR_INSATTR, UWA_LDAP_CR_ONRATTR);

   free(um);
   free(base);
   return (ret);
}


/* -------------------- Type Check ---------------- */

/* Get a list of types for an id.  The list is passed as an argument
   to uw_auth_chk_type.
   The list must be freed by uw_auth_free_types, */

void *uw_auth_get_types(LdapConfig *cfg, char *id)
{
   LDAP *ld;
   char **types;

  //  if (!cfg->ldap) uw_auth_connect(cfg);
    if (!(ld=(LDAP*)cfg->ldap)) return 0;

   get_attr_for_id(ld, cfg, id, UWA_LDAP_TYPATTR, &types);
   return ((void*)types);
}

void uw_auth_free_types(void *types)
{
   char *t;
   for (t=(char*)types;*t;t++) free (t);
   free (types);
}


/* Check if an id is a particular type 
   Returns 1 if is that type, 0 if not. */

static int chk_type_list(char **types, char *type)
{
   while (types && *types) {
      if (!strcasecmp(type, types[0])) return (1);
      types++;
   }
   return (0);
}

int uw_auth_chk_type(void *types, char *type)
{
   if (chk_type_list((char**)types,type)) return (1);
   return (0);
}


/* Disconnect from the ldap server. 
 */

void uw_auth_disconnect(LdapConfig *cfg)
{
   if (cfg->ldap) {
      ldap_unbind((LDAP*)cfg->ldap);
      cfg->ldap = NULL;
   }
}




/* ----- Private procedures -------------------------------- */

/* This list holds member groups that we need to look at */

typedef struct List__ {
   struct List__ *next;
   char *text;
} List_, *List;

static void listadd(List *root, char *text) 
{
   List l = (List) malloc(sizeof(List_));
   l->next = *root;
   *root = l;
   l->text = strdup(text);
}

static void listfree(List l) 
{
   List a,b;
   for (a=l;a;a=b) {
      b = a->next;
      free (a->text);
      free (a);
   }
}


/* Test if a person is in the group */

static int chk_in_group(LDAP *ld, LdapConfig *cfg, char *group, char *um, int dpth) 
{
    LDAPMessage    *result, *e;
    BerElement    *ber;
    char        *a, *dn;
    char        **vals;
    int        i;
    int idok = 0;

    char *filter;
    char spacer[20];
 
    List grp_mbrs = NULL;
    List gmb;
    char *attrs[8];

    if (dpth>19) return (0);  /* arbitrary limit to prevent looping */
    for (i=0;i<dpth;spacer[i++] = ' ');
    spacer[i] = '\0';
    PRINTF("%s chk_in_group: %s in %s\n", spacer, um, group);

    /* Look for the exact member match  */

    filter = (char*) malloc(strlen(UWA_LDAP_GR_NAMEATTR)+strlen(group)+strlen(UWA_LDAP_GR_MBRATTR)+strlen(um)+20);
    sprintf(filter,"(&(%s=%s)(%s=%s))", UWA_LDAP_GR_NAMEATTR, group, UWA_LDAP_GR_MBRATTR, um);
       
    attrs[0] = UWA_LDAP_GR_NAMEATTR;
    attrs[1] = NULL;

    PRINTF("filter: %s\n", filter);
    PRINTF("base: %s\n", UWA_LDAP_GR_BASE);
    if ( ldap_search_s( ld, UWA_LDAP_GR_BASE, LDAP_SCOPE_SUBTREE,
        filter, attrs, 0, &result ) != LDAP_SUCCESS ) {
        ldap_perror( ld, "ldap_search_s" );
        if ( result == NULL ) {
            ldap_unbind( ld );
            free(filter);
            return( 0 );
        }
    }

    for ( e = ldap_first_entry( ld, result ); e!=NULL && !idok;
          e = ldap_next_entry( ld, e ) ) {
       if ((vals = ldap_get_values( ld, e, UWA_LDAP_GR_NAMEATTR)) != NULL ) {
          /* this just for debug */
          for ( i = 0; vals[i]!=NULL && !idok; i++ ) {
             PRINTF( "%s=%s\n", UWA_LDAP_GR_NAMEATTR, vals[i] );
          }
          ldap_value_free( vals );
          idok = 1;
       }
    }
    ldap_msgfree( result );
    free (filter);

    if (idok) return (1);
    PRINTF( " not yet, check groups\n");

    /* Next, look for any group members. */ 

    filter = (char*) malloc(strlen(UWA_LDAP_GR_NAMEATTR)+strlen(group)+strlen(UWA_LDAP_GR_GMBRATTR)+20);
    sprintf(filter,"(&(%s=%s)(%s=*))", UWA_LDAP_GR_NAMEATTR, group, UWA_LDAP_GR_GMBRATTR, um);
       
    /* sprintf(filter,"(%s=%s)", UWA_LDAP_GR_NAMEATTR, group); */
    attrs[0] = UWA_LDAP_GR_GMBRATTR;
    attrs[1] = NULL;

    PRINTF("filter: %s\n", filter);
    if ( ldap_search_s( ld, UWA_LDAP_GR_BASE, LDAP_SCOPE_SUBTREE,
        filter, attrs, 0, &result ) != LDAP_SUCCESS ) {
        ldap_perror( ld, "ldap_search_s" );
        if ( result == NULL ) {
            ldap_unbind( ld );
            free(filter);
            return( 0 );
        }
    }

    for ( e = ldap_first_entry( ld, result ); e!=NULL && !idok;
          e = ldap_next_entry( ld, e ) ) {
       if ((vals = ldap_get_values( ld, e, UWA_LDAP_GR_GMBRATTR)) != NULL ) {
          for ( i = 0; vals[i]!=NULL && !idok; i++ ) {
             PRINTF( " %s=%s\n", UWA_LDAP_GR_GMBRATTR, vals[i] );
             listadd(&grp_mbrs, vals[i]+strlen(UWA_LDAP_GR_NAMEATTR)+1);
          }
          ldap_value_free( vals );
       }
    }
    ldap_msgfree( result );
    free (filter);

    /* Look for the id in the subgroups */ 

    for (gmb=grp_mbrs; gmb && !idok; gmb=gmb->next) {
       idok = chk_in_group(ld, cfg, gmb->text, um, dpth+1);
    }
    listfree(grp_mbrs);

    return( idok );
}


/* Test if a person matches a course attribute */

static int chk_in_crs_group(LDAP *ld, LdapConfig *cfg, char *base,
    char *sln, char *um, char *atr1, char *atr2, char *atr3) 
{
    LDAPMessage    *result, *e;
    BerElement    *ber;
    char        **vals;
    int        i, a;
    int idok = 0;

    char *filter;
    char *attrs[8];

    PRINTF("chk_in_crs_group: %s in %s\n", um, sln);

    filter = (char*) malloc(strlen(UWA_LDAP_CR_NAMEATTR)+strlen(sln)+8);
    sprintf(filter,"(%s=%s)", UWA_LDAP_CR_NAMEATTR, sln);

    attrs[0] = atr1;
    attrs[2] = atr2;
    attrs[3] = atr3;
    attrs[4] = NULL;

    if ( ldap_search_s( ld, base, LDAP_SCOPE_ONELEVEL,
            filter, attrs, 0, &result ) != LDAP_SUCCESS ) {
        ldap_perror( ld, "ldap_search_s" );
        if ( result == NULL ) {
            ldap_unbind( ld );
            free(filter);
            return( 0 );
        }
    }

    for ( e = ldap_first_entry( ld, result ); e!=NULL && !idok;
          e = ldap_next_entry( ld, e ) ) {

      for (a=0;(a<4) && attrs[a] && !idok;a++) {
        if ((vals = ldap_get_values( ld, e, attrs[a])) != NULL ) {
          for ( i = 0; vals[i]!=NULL && !idok; i++ ) {
             PRINTF( "%s: %s\n", attrs[a], vals[i] );
             if (!strcasecmp(vals[i], um)) idok = 1;
          }
          ldap_value_free( vals );
        }
      }

    }
    ldap_msgfree( result );

    return (idok);
}

/* Get an attribute's values for an id */

static int get_attr_for_id(LDAP *ld, LdapConfig *cfg, char *id, char *attr, char ***values) 
{
    LDAPMessage    *result, *e;
    BerElement    *ber;
    char        *dn;
    char        **vals;
    int        i;
    int nv = 0;
    int nva = 0;
    char **rv = NULL;
    char filter[64];
    char *attrs[2];

    PRINTF(" attr (%s) for id (%s)\n", attr, id);

    sprintf(filter, "(|(uwNetID=%s)(uwPriorNetID=%s))", id, id);
    attrs[0] = attr;
    attrs[1] = NULL;
    if ( ldap_search_s( ld, UWA_LDAP_USR_BASE, LDAP_SCOPE_SUBTREE,
        filter, attrs, 0, &result ) != LDAP_SUCCESS ) {
        ldap_perror( ld, "ldap_search_s" );
        if ( result == NULL ) {
            ldap_unbind( ld );
            return( 0 );
        }
    }

    for ( e = ldap_first_entry( ld, result ); e!=NULL;
        e = ldap_next_entry( ld, e ) ) {
        if ( (dn = ldap_get_dn( ld, e )) != NULL ) {
            PRINTF( "dn: %s\n", dn );
            ldap_memfree( dn );
        }
        if ((vals = ldap_get_values( ld, e, attr)) != NULL ) {
            for ( i = 0; vals[i]!=NULL; i++ ) {
                if ((nv+2)>nva) {
                   nva += 10;
                   rv = realloc(rv, nva*sizeof(char*));
                }
                rv[nv++] = strdup(vals[i]);
                rv[nv] = NULL;
            }
        }
        ldap_value_free( vals );
    }
    ldap_msgfree( result );
    *values = rv;
    return (nv);
}


