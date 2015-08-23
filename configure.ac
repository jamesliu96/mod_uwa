#  ========================================================================
#  Copyright (c) 2005 The University of Washington
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#  ========================================================================
#

# Configuration script for mod_uwa

AC_INIT
AC_CONFIG_HEADER([config.h])
AC_LANG(C)

# The module's name and version

AH_VERBATIM([MOD_UWA_NAME],
[/* The apache module's name */
#define MOD_UWA_NAME "mod_uwa"])


# When you change the version remember to run autoheader
AH_VERBATIM([MOD_UWA_VERSION],
[/* The module's version */
#define MOD_UWA_VERSION "3.2.1"])

# Distribution name for "make dist"
AC_SUBST(DISTNAME, "mod_uwa-3.2.1")


#-----------------------------------------

# check system type

AC_MSG_CHECKING(OS type)
ARCH="`uname`"
AC_MSG_RESULT($ARCH)

AIX_LDFLAGS=
need_slib_clean=

case $ARCH in
    AIX*)
#         AIX needs additional loader help
          aix_system=yes
          AIX_LDFLAGS="-Wl,-bE:mod_uwa.exp -Wl,-bnoentry -Wl,-lcrypto"
          need_slib_clean="need_slib_clean"
          ;;
esac

AC_AIX
AC_PROG_CC
# AC_PROG_LIBTOOL
AC_PROG_INSTALL
AC_PATH_PROG(RM, rm, rm)
AC_PATH_PROG(CP, cp, cp)
AC_PATH_PROG(TAR, tar, tar)
AC_PATH_PROG(GZIP, gzip, gzip)
AC_PATH_PROG(MV, mv, mv)
AC_PATH_PROG(CHMOD, chmod, chmod)
AC_PATH_PROG(HOST, host, host)
AC_PATH_PROG(HOSTNAME, hostname, hostname)
AC_PATH_PROG(GREP, grep, grep)
AC_PATH_PROG(SED, sed, sed)



AC_SUBST(AIX_LDFLAGS, "$AIX_LDFLAGS")
AC_SUBST(NEED_SLIB_CLEAN, "$need_slib_clean")


# Which type of module?  dso or static

# look for the static module build
apache_src=
AC_MSG_CHECKING(for apache src)
AC_ARG_WITH(apache-src,
[  --with-apache-src=DIR   Build static Apache module.  DIR is the path
                           to the top-level Apache source directory.],
[
   if test "$withval" = "yes"; then
      AC_MSG_ERROR(You need to specify a directory with --with-apache-src)
   fi
   if test -d $withval/modules && \
      test -f $withval/include/httpd.h; then  # apache2
         APACHE_VERSION=2
         apache_src=$withval
         apache_target=$withval/modules/uwa
         apache_src_ref=$PWD
#        I can't get it to work on apache2
         AC_MSG_ERROR(Cannot build static Apache 2 module)
   fi
   if test -d $withval/src/modules && \
      test -f $withval/src/include/httpd.h; then
         APACHE_VERSION=1_3
         AC_DEFINE(APACHE1_3, 1, [Define to 1 fro 1.3 version])
         apache_src=$withval
         apache_target=$withval/src/modules/uwa
         apache_src_ref=$PWD
   fi
   if test "x$apache_src" = "x"; then
         AC_MSG_ERROR(Cannot find the apache source)
   fi
   APXS=
   # in static case, we don't build
   AC_SUBST(apache_module, "")
   AC_MSG_RESULT($withval)

],[
    AC_MSG_RESULT(no)
])


# Look for apxs (dso version)

AC_ARG_WITH(apxs,
    AC_HELP_STRING([--with-apxs=PATH],[/path/to/apxs]),
[ case "$withval" in
   no)
      OLDPATH=$PATH
      PATH="/usr/local/apache/bin:/usr/local/apache2/bin:/usr/www/bin:/usr/sbin:$PATH"
      AC_PATH_PROG(APXS, apxs)
      PATH=$OLDPATH
      ;;
    *)
      OLDPATH=$PATH
      if test -d "$withval"; then
          PATH="$withval:$PATH"
          AC_PATH_PROG(APXS, apxs)
      else
          PATH=`dirname $withval`":$PATH"
          PROG=`basename $withval`
          AC_PATH_PROG(APXS, $PROG)
      fi
      PATH=$OLDPATH
      ;;
  esac ],[
 if test "x$apache_src" = "x"; then
     PATH="/usr/local/apache/bin:/usr/local/apache2/bin:/usr/www/bin:/usr/sbin:$PATH"
     AC_PATH_PROG(APXS, apxs)
 fi
])

# Find out which apache we're working for

if ! test "x$APXS" = "x"; then
 AC_SUBST(APACHE_PREFIX, `$APXS -q PREFIX`)
 AC_MSG_CHECKING([Apache version])
 APACHE_VERSION=
 XVERSION=
 # maybe can just ask the server
 httpd="`$APXS -q SBINDIR`/`$APXS -q TARGET`"
 if test "x$httpd" != "x"; then
     v=`$httpd -v|$SED -n -e 's/.*Apache\/\.*//p'`
     case $v in
       1.3.*) APACHE_VERSION="1_3"
              ;;
       2.*)   APACHE_VERSION="2"
              XVERSION="$v"
              ;;
     esac
 fi
 if test "x$APACHE_VERSION" = "x"; then
   # try the include files
   OCFLAGS=$CFLAGS
   APXS_INC=`$APXS -q INCLUDEDIR`
   APXS_DEF=`$APXS -q EXTRA_CPPFLAGS`
   CFLAGS="$CFLAGS -I$APXS_INC $APXS_DEF"

   AC_TRY_RUN( [
     /* Look for 1.x version */
     #include <stdlib.h>
     #include <httpd.h>

     int main() {
         exit( ( APACHE_RELEASE > 10300000 &&
                 APACHE_RELEASE < 10400000 ) != 1 );
     }
     ],
       [APACHE_VERSION="1_3"],
     [
     ]
   )
   if test "x$APACHE_VERSION" = "x"; then
     AC_TRY_RUN( [
       /* Look for 2.x version */
       #include <stdlib.h>
       #include <httpd.h>

       int main() {
           exit( *AP_SERVER_MAJORVERSION!='2');
       }
       ],
         [APACHE_VERSION="2"],
       [
         AC_MSG_ERROR([Apache version 1.3.x or 2.x is required!])
       ]
     )
   fi
   CFLAGS=$OCFLAGS
 fi

 if test "$APACHE_VERSION" = "2"; then
    AC_DEFINE(APACHE2, 1, [Define to 1 for 2.x version])
    AC_SUBST(APACHE_MOD_EXT, "la")
 fi

 if test "$APACHE_VERSION" = "1_3"; then
    AC_DEFINE(APACHE1_3, 1, [Define to 1 for 1.3 version])
    AC_SUBST(APACHE_INSTALLBUILDDIR, `$APXS -q exp_installbuilddir`)
    AC_SUBST(APACHE_MOD_EXT, "so")
 fi


 AC_MSG_RESULT([$APACHE_VERSION ($XVERSION)])
 AC_SUBST(APACHE_VERSION, $APACHE_VERSION)
 AC_SUBST(APACHE_MOD_EXT, $APACHE_MOD_EXT)
 AC_SUBST(APACHE_INSTALLBUILDDIR, `$APXS -q exp_installbuilddir`)

fi # if apxs

# Make sure we're doing something

if test "x$APXS" = "x" && \
   test "x$apache_src" = "x"; then
    AC_MSG_ERROR([Can't find apxs or an apache source], 1)
fi


# -- Find openssl -----------------------



ssl_inc=
ssl_lib=
ssl_openssl=openssl

AC_ARG_WITH(ssl,
    AC_HELP_STRING([--with-ssl=PATH], [Openssl lib/include root]),
[ case "$withval" in
   no)
     ;;
   *)
     ssl_inc="-I$withval/include"
     ssl_lib="-L$withval/lib"
     ssl_openssl="$withval/bin/openssl"
     ;;
  esac ])

AC_ARG_WITH(ssl-inc-dir,
    AC_HELP_STRING([--with-ssl-inc-dir=PATH], [Openssl include path]),
[ case "$withval" in
   no)
     ;;
   *)
     ssl_inc="-I$withval"
     ;;
  esac ])

AC_ARG_WITH(ssl-lib-dir,
    AC_HELP_STRING([--with-ssl-lib-dir=PATH], [Openssl lib path]),
[ case "$withval" in
   no)
     ;;
   *)
     ssl_lib="-L$withval"
     ;;
  esac ])


CPPFLAGS="$CPPFLAGS $ssl_inc"
LDFLAGS="$LDFLAGS $ssl_lib"

AC_CHECK_LIB(ssl, main)


# Look for openssl krb5 includes

AC_MSG_CHECKING([for openssl krb5 includes])
vfi=
vfa=
for vf in `$ssl_openssl version -f`
do
    case $vf in
      -I*) vfi="$vfi $vf"
           ;;
    esac
    vfa="yes"
done
if test "x$vfi" != "x" ; then
    CPPFLAGS="$CPPFLAGS $vfi"
    AC_MSG_RESULT([$vfi])
else
    if test "x$vfa" != "x"; then
       AC_MSG_RESULT([none])
    else
       AC_MSG_WARN([could not run openssl to find includes])
    fi
fi


AC_CHECK_LIB(crypto,ERR_load_ASN1_strings,,
             AC_MSG_ERROR([Could not find a usable libcrypto.]))
AC_CHECK_HEADERS([openssl/ssl.h])



# Find the kerberos libraries

k5_lib=
k5_inc=

AC_ARG_WITH(krb5,
    AC_HELP_STRING([--with-krb5=PATH], [KRB5 lib/include root]),
[ case "$withval" in
   no)
      k5_lib=no
      ;;
   yes)
      #  We could look around at random for Kerberos support, but that
      #  shouldn't override files found by default by the compiler, or
      #  on search paths supplied to configure, and I can't think of any
      #  way to avoid it.
      #  So, for example your Heimdal installation puts include files in
      #  /usr/include/krb5 and /usr/include/gssapi, and that's what you
      #  want to use, you have to know that and specify, like
      #  CPPFLAGS='-I/usr/include/krb5 -I/usr/include/gssapi' ./configure
      k5_lib=
      ;;
   *)
       k5saslmsg="You did krb5"
      k5_lib="-L$withval/lib"
      k5_inc="-I$withval/include"

      #  Prepend, because Red Hat adds their -I/usr/kerberos by default
      #  and specified location should take precedence.
      CPPFLAGS="$k5_inc $CPPFLAGS"
      LDFLAGS="$LDFLAGS $k5_lib"
      ;;
   esac ])



case $k5_lib in
no)
   ;;
*)
   #  (begin checking Kerberos libraries)
   AC_CHECK_HEADERS([com_err.h krb5.h])
   #  -lresolv is rarely needed, but it's inconvenient to test that
   #  at this point.  Hopefully it won't hurt in any case.
   AC_CHECK_LIB(resolv, main)
   #  Any reasonably recent MIT distribution will have k5crypto.  If we
   #  have it, go on to expect MIT.
   AC_CHECK_LIB(k5crypto, main)
   case $LIBS in
   *k5crypto*)
      #  Must be MIT Kerberos
      #  Since 1.4, com_err et al. depend on krb5support.
      AC_CHECK_LIB(krb5support, main)
      AC_CHECK_LIB(com_err, main)
      AC_CHECK_LIB(krb5, main)
      AC_CHECK_LIB(gssapi_krb5, main)
      #  (end MIT Kerberos)
      ;;
   *)
      #  No k5crypto here, must be Heimdal Kerberos
      AC_CHECK_LIB(com_err, main)
      AC_CHECK_LIB(roken, main)
      AC_CHECK_LIB(asn1, main)
      AC_CHECK_LIB(krb5, main)
      AC_CHECK_LIB(gssapi, main)
      #  (end Heimdal Kerberos)
      ;;
   esac
   #  (end checking Kerberos libraries)
   ;;
esac


# -- Find sasl2 -----------------------



sasl_inc=
sasl_lib=

AC_ARG_WITH(sasl2,
    AC_HELP_STRING([--with-sasl2=PATH], [sasl2 lib/include root]),
[ case "$withval" in
   no)
     ;;
   *)
     sasl_inc="-I$withval/include"
     sasl_lib="-L$withval/lib"
     ;;
  esac ])

AC_ARG_WITH(sasl2-inc-dir,
    AC_HELP_STRING([--with-sasl2-inc-dir=PATH], [sasl2 include path]),
[ case "$withval" in
   no)
     ;;
   *)
     sasl_inc="-I$withval"
     ;;
  esac ])

AC_ARG_WITH(ssl-lib-dir,
    AC_HELP_STRING([--with-sasl2-lib-dir=PATH], [sasl2 lib path]),
[ case "$withval" in
   no)
     ;;
   *)
     sasl_lib="-L$withval"
     ;;
  esac ])


CPPFLAGS="$CPPFLAGS $sasl_inc"
LDFLAGS="$LDFLAGS $sasl_lib"

AC_CHECK_LIB(sasl2, sasl_client_init,,
 if test "x$k5_lib" = "x"; then
   AC_MSG_ERROR([cannot find usable sasl2 library - specify a krb5 path], 1)
  else
   AC_MSG_ERROR([cannot find usable sasl2 library], 1)
  fi
)


# --- Find ldap --------------------------

ldap_inc=
ldap_lib=
AC_ARG_WITH(ldap,
    AC_HELP_STRING([--with-ldap=PATH], [LDAP root]),
[ case "$withval" in
   no)
     ;;
   yes)
     ;;
   *)
     ldap_inc="-I$withval/include"
     ldap_lib="-L$withval/lib"
     ;;
  esac ])

AC_ARG_WITH(ldap-inc-dir,
    AC_HELP_STRING([--with-ldap-inc-dir=PATH], [LDAP include path]),
[ case "$withval" in
   no)
     ;;
   *)
     ldap_inc="-I$withval"
     ;;
  esac ])

AC_ARG_WITH(ldap-lib-dir,
    AC_HELP_STRING([--with-ldap-lib-dir=PATH], [LDAP lib path]),
[ case "$withval" in
   no)
     ;;
   *)
     ldap_lib="-L$withval"
     ;;
  esac ])

   
CPPFLAGS="$CPPFLAGS $ldap_inc"
LDFLAGS="$LDFLAGS $ldap_lib"

AC_CHECK_HEADERS([lber.h])
AC_CHECK_HEADERS([ldap.h],,,[#include <lber.h>])


AC_MSG_CHECKING([if LDAP API is OpenLDAP])
AC_TRY_RUN( [ 
  #include <ldap.h>

    int main() {
        exit( strcmp(LDAP_VENDOR_NAME, "OpenLDAP") );
    }
                ],
                [ AC_MSG_RESULT([yes])
                  AC_DEFINE( LDAP_OPENLDAP, 1,
                             [Define to 1 if the LDAP library is OpenLDAP] )
                  LDAP_OPENLDAP=1
                ],
                [ AC_MSG_RESULT([no])
                  LDAP_OPENLDAP=0
                ],
                AC_MSG_ERROR( "Cross-Compiling not supported."  ) )

if test "$APACHE_VERSION" = "2"; then
   ldaplibname=ldap_r 
   pthread="-lpthread"
else 
   ldaplibname=ldap
   pthread=
fi
if test "$LDAP_OPENLDAP" = "1"; then
    AC_CHECK_LIB(lber, ber_init,,
        AC_MSG_ERROR([cannot find usable lber library], 1), [$pthread])
    AC_CHECK_LIB($ldaplibname, ldap_init,,
        AC_MSG_ERROR([cannot find usable $ldaplibname library], 1), [-llber $pthread])
    AC_CHECK_LIB(lber, ldap_int_sasl_init,,
        AC_MSG_ERROR([OpenLDAP does not have sasl support], 1), [$pthread])
else

    AC_MSG_CHECKING([if LDAP API is Netscape])
    AC_TRY_RUN( [ 
        #include <lber.h>
        #include <ldap.h>

        int main() {

        if ( (strcmp(LDAP_VENDOR_NAME, "Netscape Communications Corp.") == 0)
            && LDAP_VENDOR_VERSION >= 400 )
            exit(0);

            exit(2);
        }
                    ],
                    [ AC_MSG_RESULT([yes])
                    AC_DEFINE( LDAP_NETSCAPE, 1,
                    [Define to 1 if the LDAP library is Netscape] )
                    LDAP_NETSCAPE=1
                    AC_CHECK_LIB(ldapssl41,main)
                    AC_CHECK_LIB(nspr3,main)
                    AC_CHECK_LIB(plc3,main)
                    AC_CHECK_LIB(plds3,main)
                    ],
                    [ AC_MSG_RESULT([no])
                    LDAP_NETSCAPE=0
                    ],
                    AC_MSG_ERROR( "Cross-Compiling not supported."  ) )

  if test "$LDAP_NETSCAPE" = "1"; then
      AC_MSG_WARN( "Netscape LDAP not really supported. You are on your own."  ) 
  else

    AC_MSG_CHECKING([if LDAP API is Sun/Netscape/iPlanet])
    AC_TRY_RUN( [ 
        #include <lber.h>
        #include <ldap.h>

        int main() {

        if ( (strcmp(LDAP_VENDOR_NAME, "Sun Microsystems Inc.") == 0)
            && LDAP_VENDOR_VERSION >= 508 )
            exit(0);

            exit(2);
        }
                    ],
                    [ AC_MSG_RESULT([yes])
                    AC_MSG_WARN( "Warning: Non-OpenLDAP API found.  YMMV." ) 
                    AC_DEFINE( LDAP_SUN, 1,
                    [Define to 1 if the LDAP library is Sun/Netscape/iPlanet] )
                    LDAP_SUN=1
                    ],
                    [ AC_MSG_RESULT([no])
                    LDAP_SUN=0
                    ],
                    AC_MSG_WARN( "Cross-Compiling not supported."  ) )


    if test "$LDAP_SUN" = "1"; then
            AC_MSG_WARN( "iPlanet LDAP not really supported. You are on your own."  ) 
            AC_CHECK_HEADERS([ldap_ssl.h ldappr.h],,,
            [ #include <lber.h>
              #include <ldap.h>
            ])
            AC_CHECK_LIB(ldap50, ldap_init)
            AC_CHECK_LIB(ssl3, SSL_AuthCertificate)
            AC_CHECK_LIB(nss3, CERT_VerifyCert)
            AC_CHECK_LIB(prldap50, prldap_init)
            AC_CHECK_LIB(ssldap50, ldapssl_init)

            if test "x$with_cert_db_path" = "x"; then
                with_cert_db_path=no
            fi

            AC_MSG_CHECKING([for cert7.db and key3.db path])
            AC_ARG_WITH(cert-db-path,
                        AC_HELP_STRING([--with-cert-db-path=PATH],
                        [cert7 and key3 db path (from a Netscape installation)]),
            [ case "$withval" in
            no)
            AC_MSG_ERROR([with-cert-db-path must be specified with Sun SDK.], 1)
            ;;
            *)
            AC_SUBST(CERT_DB_PATH, "$withval")
            AC_MSG_RESULT($withval)
            ;;
        esac ])
    fi

  fi
fi

# Save the compiler and linker flags

AC_SUBST(LDFLAGS, "$LDFLAGS")
AC_SUBST(CPPFLAGS, "$CPPFLAGS")


# AM_MAINTAINER_MODE


# setup the correct Makefile input
if test "x$APXS" != "x";  then
  if test "$APACHE_VERSION" = "2"; then
     ln -sf Makefile.in.ap2 Makefile.in
  else 
     ln -sf Makefile.in.ap1 Makefile.in
  fi
  AC_CONFIG_FILES([Makefile])
  AC_OUTPUT()
fi

# copy sources to apache tree if static module

if test "x$apache_src" != "x"; then
  echo "Copying apache module sources to $apache_target."

   AC_CONFIG_FILES([libuwa.module])
   AC_OUTPUT()

   if ! test -d $apache_target; then
      mkdir $apache_target
   fi
   if ! test -d $apache_target; then
      AC_MSG_ERROR([Could not create $apache_target])
   fi

   cpsrc="Makefile.tmpl libuwa.module \
          ldaplib.c mod_uwa.c uwa_crypt.c \
          config.h ldaplib.h uwa_crypt.h"

   for f in $cpsrc
   do
     cp -p $f $apache_target
   done

   cat > $apache_target/Makefile.libdir <<'END'
# dummy
END 
fi #if apache_src

# AC_CONFIG_FILES([stamp-h], [echo timestamp > stamp-h])


# Save the location of apache into the "apache_dir" variable.
# The AC_SUBST macro causes the variable to be saved in config.status
AC_SUBST(apache_dir)


# Write config.status and the Makefile
AC_OUTPUT()

# finish with advisories

# config of apache src
if test "x$apache_src" != "x"; then
   echo ""
   echo "Reminder: You must reconfigure apache with "
   echo "           --activate-module=src/modules/uwa/libuwa.a"
   echo ""
fi

