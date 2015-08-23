/* ldap group library */

#include <sys/types.h>


/* ---- ldap defaults: these must match the ldap schema - */

/* server hostname */
#define UWA_LDAP_HOST         "groups.u.washington.edu"

/* ports for plain and ssl connections */
#define UWA_LDAP_PORT          389

/* Base of group searches */
#define UWA_LDAP_GR_BASE      "ou=groups,dc=washington,dc=edu"

/* Base of userid searches */
#define UWA_LDAP_USR_BASE     "dc=washington,dc=edu"

/* Base of courses searches */
#define UWA_LDAP_CR_BASE      "ou=courses,dc=washington,dc=edu"
/* base is actually "ou=QQQYYYY,ou=courses,..." */

/* formst to make member attribute value from userid */
#define UWA_LDAP_GR_MBRFMT   "uwnetid=%s"

/* formst to make member attribute value from eppn */
#define UWA_LDAP_GR_EPPNFMT   "eduPersonPrincipalName=%s"

/* attribute of group names */
#define UWA_LDAP_GR_NAMEATTR      "cn"

/* attribute of group members */
#define UWA_LDAP_GR_MBRATTR      "member"

/* attribute of group members who are groups */
#define UWA_LDAP_GR_GMBRATTR     "memberGroup"

/* attribute of group owners */
#define UWA_LDAP_GR_ONRATTR      "owner"

/* formst to make course attribute value from sln */
#define UWA_LDAP_CR_MBRFMT   "uwnetid=%s"

/* attribute of sln names */
#define UWA_LDAP_CR_NAMEATTR      "sln"

/* attribute of course student members */
#define UWA_LDAP_CR_STDATTR      "student"

/* attribute of course instructors members */
#define UWA_LDAP_CR_INSATTR      "instructor"

/* attribute of other course owners */
#define UWA_LDAP_CR_ONRATTR      "owner"

/* attribute of user type codes */
#define UWA_LDAP_TYPATTR      "eduPersonAffiliation"

/* local eppn domain */
#define UWA_EPPN_DEFAULT  "@washington.edu"



/* -------- ldap context ------------------------ */


typedef struct LdapConfig_ {
  void *ldap;      /* an LDAP connection */
  char *host;
  int port;
  char *certdb;    /* certdb */
  char *bindcrt;   /* cert for bind */
  char *bindkey;   /* key for cert bind */
  char *binddn;    /* principal */
  char *bindpw;    /* pw */
#ifdef ENABLE_KRB5
  char *k5prin;     /* k5 principal */
  char *k5ktab;     /* k5 keytab */
#endif
  int  gssapi;
} LdapConfig;


/* interfaces  */

LdapConfig *new_ldap_cfg();
int uw_auth_connect(LdapConfig *cfg, request_rec *r);

int uw_auth_chk_in_group(LdapConfig *cfg, char *id, char *group);

int uw_auth_chk_in_course(LdapConfig *cfg, char *id, char *course, char *onr);

void *uw_auth_get_types(LdapConfig *cfg, char *id);

void uw_auth_free_types(void *types);

int uw_auth_chk_type(void *types, char *type);

void uw_auth_disconnect(LdapConfig *cfg);


