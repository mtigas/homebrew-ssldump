require 'formula'

class Ssldump < Formula
  homepage 'http://www.rtfm.com/ssldump/'
  url 'http://www.rtfm.com/ssldump/ssldump-0.9b3.tar.gz'
  sha1 'a633a9a811a138eac5ed440d583473b644135ef5'

  depends_on 'openssl'

  # reorder include files
  # http://sourceforge.net/tracker/index.php?func=detail&aid=1622854&group_id=68993&atid=523055
  # increase pcap sample size from an arbitrary 5000 the max TLS packet size 18432
  # openssl compat: (extracted from http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=337453 )
  def patches
    DATA
  end

  def install
    ENV["LIBS"] = "-lssl -lcrypto"

    # .dylib, not .a
    inreplace "configure", "if test -f $dir/libpcap.a; then",
                           "if test -f $dir/libpcap.dylib; then"

    openssl = Formula.factory('openssl')

    system "./configure", "--disable-debug",
                          "--disable-dependency-tracking",
                          "--prefix=#{prefix}",
                          "--with-openssl=#{openssl.prefix}",
                          "osx"
    system "make"
    bin.install "ssldump"
    man1.install "ssldump.1"
  end
end

__END__
--- a/base/pcap-snoop.c	2010-03-18 22:59:13.000000000 -0700
+++ b/base/pcap-snoop.c	2010-03-18 22:59:30.000000000 -0700
@@ -46,10 +46,9 @@
 
 static char *RCSSTRING="$Id: pcap-snoop.c,v 1.14 2002/09/09 21:02:58 ekr Exp $";
 
-
+#include <net/bpf.h>
 #include <pcap.h>
 #include <unistd.h>
-#include <net/bpf.h>
 #ifndef _WIN32
 #include <sys/param.h>
 #endif
--- a/base/pcap-snoop.c	2012-04-06 10:35:06.000000000 -0700
+++ b/base/pcap-snoop.c	2012-04-06 10:45:31.000000000 -0700
@@ -286,7 +286,7 @@
           err_exit("Aborting",-1);
         }
       }
-      if(!(p=pcap_open_live(interface_name,5000,!no_promiscuous,1000,errbuf))){
+      if(!(p=pcap_open_live(interface_name,18432,!no_promiscuous,1000,errbuf))){
 	fprintf(stderr,"PCAP: %s\n",errbuf);
 	err_exit("Aborting",-1);
       }
--- a/ssl/ssldecode.c	2013-07-10 14:44:42.000000000 -0400
+++ b/ssl/ssldecode.c	2013-07-10 14:44:44.000000000 -0400
@@ -51,6 +51,7 @@
 #include <openssl/ssl.h>
 #include <openssl/hmac.h>
 #include <openssl/evp.h>
+#include <openssl/md5.h>
 #include <openssl/x509v3.h>
 #endif
 #include "ssldecode.h"
@@ -131,7 +132,8 @@
     ssl_decode_ctx *d=0;
     int r,_status;
     
-    SSLeay_add_all_algorithms();
+    SSL_library_init();
+    OpenSSL_add_all_algorithms();
     if(!(d=(ssl_decode_ctx *)malloc(sizeof(ssl_decode_ctx))))
       ABORT(R_NO_MEMORY);
     if(!(d->ssl_ctx=SSL_CTX_new(SSLv23_server_method())))
