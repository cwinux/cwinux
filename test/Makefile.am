##  Process this file with automake to create Makefile.in

includedir =
pkgconfigdir =

BUILD_DATE=$(shell date +%F)


bin_PROGRAMS =test_ssl

test_ssl_CPPFLAGS = -D_BUILD_DATE="$(BUILD_DATE)" -W -Wall
test_ssl_SOURCES = test_ssl.cpp
test_ssl_LDADD=
test_ssl_LDFLAGS=

LIBS=-L../lib/cmn/src/.libs -L../lib/app/src/.libs -L../lib/net/src/.libs -lcwxcmn -lcwxnet -lcwxapp -lssl -lcrypto -lz -lpthread -ldl -lrt
INCLUDES=-I../lib/cmn/include -I../lib/net/include -I../lib/net/include

## Clean up template repositories, etc.
clean-local:
	-rm -f *~ *.bak *.rpo *.sym lib*.*_pure_* core core.*
