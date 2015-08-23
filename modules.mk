# Data for apache 2 module build
#

MOD_UWA=mod_uwa ldaplib uwa_crypt

mod_uwa.la: ${MOD_UWA:=.slo}
	$(SH_LINK) -rpath $(libexecdir) -module \
	-avoid-version ${MOD_UWA:=.lo} $(UWADEPLIBS) 

DISTCLEAN_TARGETS = modules.mk

shared =  mod_uwa.la

