
# Metasploitable/Apache

Apache vulnerabilities by version: https://httpd.apache.org/security/vulnerabilities_22.html
Contents [hide]

    1 Metasploit HTTP Modules
        1.1 Where to Start
        1.2 dir listing
        1.3 dir scanner
        1.4 files dir
            1.4.1 Telnet to Explore 301s
            1.4.2 Fixed Telnet Request
            1.4.3 Fuzzing?
        1.5 Open Proxy Servers
    2 Metasploit Apache Modules
        2.1 Whaaaat Where to Begin
        2.2 Mod Negotiation Scanner
        2.3 Mod Negotiation Brute
    3 Flags

Metasploit HTTP Modules

First, here's a list of the scanner modules related to HTTP: https://www.offensive-security.com/metasploit-unleashed/scanner-http-auxiliary-modules/

This has a number of interesting modules to do the following:

    check if https certificates are expired
    check if directory listings are enabled on servers
    scan for directories
    bypass authentication using webdav unicode vulnerability [1]
    use delicious.com to farm links
    use archive.org to farm links
    check for presence of interesting files
    brute-force https login
    look for open proxy servers
    query IP addresses for web servers and capabilities
    find robots.txt
    grab SSL certificate information
    get web server version
    brute-force tomcat manager application login
    bpyass authentication using different HTTP verbs
    scan servers for webdav, content disclosure via webdav
    brute-force Wordpress logins

msf > use auxiliary/scanner/http/
Display all 197 possibilities? (y or n)
use auxiliary/scanner/http/a10networks_ax_directory_traversal         use auxiliary/scanner/http/hp_imc_reportimgservlt_traversal           use auxiliary/scanner/http/robots_txt
use auxiliary/scanner/http/accellion_fta_statecode_file_read          use auxiliary/scanner/http/hp_imc_som_file_download                   use auxiliary/scanner/http/s40_traversal
use auxiliary/scanner/http/adobe_xml_inject                           use auxiliary/scanner/http/hp_sitescope_getfileinternal_fileaccess    use auxiliary/scanner/http/sap_businessobjects_user_brute
use auxiliary/scanner/http/allegro_rompager_misfortune_cookie         use auxiliary/scanner/http/hp_sitescope_getsitescopeconfiguration     use auxiliary/scanner/http/sap_businessobjects_user_brute_web
use auxiliary/scanner/http/apache_activemq_source_disclosure          use auxiliary/scanner/http/hp_sitescope_loadfilecontent_fileaccess    use auxiliary/scanner/http/sap_businessobjects_user_enum
use auxiliary/scanner/http/apache_activemq_traversal                  use auxiliary/scanner/http/hp_sys_mgmt_login                          use auxiliary/scanner/http/sap_businessobjects_version_enum
use auxiliary/scanner/http/apache_mod_cgi_bash_env                    use auxiliary/scanner/http/http_header                                use auxiliary/scanner/http/scraper
use auxiliary/scanner/http/apache_userdir_enum                        use auxiliary/scanner/http/http_hsts                                  use auxiliary/scanner/http/sentry_cdu_enum
use auxiliary/scanner/http/appletv_login                              use auxiliary/scanner/http/http_login                                 use auxiliary/scanner/http/servicedesk_plus_traversal
use auxiliary/scanner/http/atlassian_crowd_fileaccess                 use auxiliary/scanner/http/http_put                                   use auxiliary/scanner/http/sevone_enum
use auxiliary/scanner/http/axis_local_file_include                    use auxiliary/scanner/http/http_traversal                             use auxiliary/scanner/http/simple_webserver_traversal
use auxiliary/scanner/http/axis_login                                 use auxiliary/scanner/http/http_version                               use auxiliary/scanner/http/smt_ipmi_49152_exposure
use auxiliary/scanner/http/backup_file                                use auxiliary/scanner/http/httpbl_lookup                              use auxiliary/scanner/http/smt_ipmi_cgi_scanner
use auxiliary/scanner/http/barracuda_directory_traversal              use auxiliary/scanner/http/iis_internal_ip                            use auxiliary/scanner/http/smt_ipmi_static_cert_scanner
use auxiliary/scanner/http/bitweaver_overlay_type_traversal           use auxiliary/scanner/http/influxdb_enum                              use auxiliary/scanner/http/smt_ipmi_url_redirect_traversal
use auxiliary/scanner/http/blind_sql_query                            use auxiliary/scanner/http/infovista_enum                             use auxiliary/scanner/http/soap_xml
use auxiliary/scanner/http/bmc_trackit_passwd_reset                   use auxiliary/scanner/http/ipboard_login                              use auxiliary/scanner/http/sockso_traversal
use auxiliary/scanner/http/brute_dirs                                 use auxiliary/scanner/http/jboss_status                               use auxiliary/scanner/http/splunk_web_login
use auxiliary/scanner/http/buffalo_login                              use auxiliary/scanner/http/jboss_vulnscan                             use auxiliary/scanner/http/squid_pivot_scanning
use auxiliary/scanner/http/canon_wireless                             use auxiliary/scanner/http/jenkins_enum                               use auxiliary/scanner/http/squiz_matrix_user_enum
use auxiliary/scanner/http/cert                                       use auxiliary/scanner/http/jenkins_login                              use auxiliary/scanner/http/ssl
use auxiliary/scanner/http/chef_webui_login                           use auxiliary/scanner/http/joomla_bruteforce_login                    use auxiliary/scanner/http/ssl_version
use auxiliary/scanner/http/chromecast_webserver                       use auxiliary/scanner/http/joomla_ecommercewd_sqli_scanner            use auxiliary/scanner/http/support_center_plus_directory_traversal
use auxiliary/scanner/http/cisco_asa_asdm                             use auxiliary/scanner/http/joomla_gallerywd_sqli_scanner              use auxiliary/scanner/http/svn_scanner
use auxiliary/scanner/http/cisco_device_manager                       use auxiliary/scanner/http/joomla_pages                               use auxiliary/scanner/http/svn_wcdb_scanner
use auxiliary/scanner/http/cisco_ios_auth_bypass                      use auxiliary/scanner/http/joomla_plugins                             use auxiliary/scanner/http/sybase_easerver_traversal
use auxiliary/scanner/http/cisco_ironport_enum                        use auxiliary/scanner/http/joomla_version                             use auxiliary/scanner/http/symantec_brightmail_logfile
use auxiliary/scanner/http/cisco_nac_manager_traversal                use auxiliary/scanner/http/linksys_e1500_traversal                    use auxiliary/scanner/http/symantec_web_gateway_login
use auxiliary/scanner/http/cisco_ssl_vpn                              use auxiliary/scanner/http/litespeed_source_disclosure                use auxiliary/scanner/http/titan_ftp_admin_pwd
use auxiliary/scanner/http/cisco_ssl_vpn_priv_esc                     use auxiliary/scanner/http/lucky_punch                                use auxiliary/scanner/http/title
use auxiliary/scanner/http/clansphere_traversal                       use auxiliary/scanner/http/majordomo2_directory_traversal             use auxiliary/scanner/http/tomcat_enum
use auxiliary/scanner/http/coldfusion_locale_traversal                use auxiliary/scanner/http/manageengine_desktop_central_login         use auxiliary/scanner/http/tomcat_mgr_login
use auxiliary/scanner/http/coldfusion_version                         use auxiliary/scanner/http/manageengine_deviceexpert_traversal        use auxiliary/scanner/http/tplink_traversal_noauth
use auxiliary/scanner/http/concrete5_member_list                      use auxiliary/scanner/http/manageengine_deviceexpert_user_creds       use auxiliary/scanner/http/trace
use auxiliary/scanner/http/copy_of_file                               use auxiliary/scanner/http/manageengine_securitymanager_traversal     use auxiliary/scanner/http/trace_axd
use auxiliary/scanner/http/crawler                                    use auxiliary/scanner/http/mediawiki_svg_fileaccess                   use auxiliary/scanner/http/typo3_bruteforce
use auxiliary/scanner/http/dell_idrac                                 use auxiliary/scanner/http/mod_negotiation_brute                      use auxiliary/scanner/http/vcms_login
use auxiliary/scanner/http/dir_listing                                use auxiliary/scanner/http/mod_negotiation_scanner                    use auxiliary/scanner/http/verb_auth_bypass
use auxiliary/scanner/http/dir_scanner                                use auxiliary/scanner/http/ms09_020_webdav_unicode_bypass             use auxiliary/scanner/http/vhost_scanner
use auxiliary/scanner/http/dir_webdav_unicode_bypass                  use auxiliary/scanner/http/ms15_034_http_sys_memory_dump              use auxiliary/scanner/http/wangkongbao_traversal
use auxiliary/scanner/http/dlink_dir_300_615_http_login               use auxiliary/scanner/http/mybook_live_login                          use auxiliary/scanner/http/web_vulndb
use auxiliary/scanner/http/dlink_dir_615h_http_login                  use auxiliary/scanner/http/netdecision_traversal                      use auxiliary/scanner/http/webdav_internal_ip
use auxiliary/scanner/http/dlink_dir_session_cgi_http_login           use auxiliary/scanner/http/netgear_sph200d_traversal                  use auxiliary/scanner/http/webdav_scanner
use auxiliary/scanner/http/dlink_user_agent_backdoor                  use auxiliary/scanner/http/nginx_source_disclosure                    use auxiliary/scanner/http/webdav_website_content
use auxiliary/scanner/http/dolibarr_login                             use auxiliary/scanner/http/novell_file_reporter_fsfui_fileaccess      use auxiliary/scanner/http/webpagetest_traversal
use auxiliary/scanner/http/drupal_views_user_enum                     use auxiliary/scanner/http/novell_file_reporter_srs_fileaccess        use auxiliary/scanner/http/wildfly_traversal
use auxiliary/scanner/http/ektron_cms400net                           use auxiliary/scanner/http/novell_mdm_creds                           use auxiliary/scanner/http/wordpress_cp_calendar_sqli
use auxiliary/scanner/http/elasticsearch_traversal                    use auxiliary/scanner/http/ntlm_info_enumeration                      use auxiliary/scanner/http/wordpress_ghost_scanner
use auxiliary/scanner/http/enum_wayback                               use auxiliary/scanner/http/open_proxy                                 use auxiliary/scanner/http/wordpress_login_enum
use auxiliary/scanner/http/error_sql_injection                        use auxiliary/scanner/http/openmind_messageos_login                   use auxiliary/scanner/http/wordpress_pingback_access
use auxiliary/scanner/http/etherpad_duo_login                         use auxiliary/scanner/http/options                                    use auxiliary/scanner/http/wordpress_scanner
use auxiliary/scanner/http/f5_bigip_virtual_server                    use auxiliary/scanner/http/oracle_demantra_database_credentials_leak  use auxiliary/scanner/http/wordpress_xmlrpc_login
use auxiliary/scanner/http/f5_mgmt_scanner                            use auxiliary/scanner/http/oracle_demantra_file_retrieval             use auxiliary/scanner/http/wp_contus_video_gallery_sqli
use auxiliary/scanner/http/file_same_name_dir                         use auxiliary/scanner/http/oracle_ilom_login                          use auxiliary/scanner/http/wp_dukapress_file_read

Whew!
Where to Start

This article will cover techniques for exploiting the Metasploitable apache server (running Apache 2.2.8). It will start with some general techniques (working for most web servers), then move to the Apache-specific.

This will also ignore the Tomcat server - we'll get to that later.

More routes to attack the Metasploitable machine are over at Metasploitable/Apache/Python
dir listing

the dir_listing module did not turn up anything useful:

msf > use auxiliary/scanner/http/dir_listing
msf auxiliary(dir_listing) > show options

Module options (auxiliary/scanner/http/dir_listing):
```
   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   PATH     /                yes       The path to identify directoy listing
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target address range or CIDR identifier
   RPORT    80               yes       The target port
   THREADS  1                yes       The number of concurrent threads
   VHOST                     no        HTTP server virtual host

```
```
msf auxiliary(dir_listing) > set RHOSTS 10.0.0.27
RHOSTS => 10.0.0.27
msf auxiliary(dir_listing) > run

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(dir_listing) >
```

dir scanner

the dir_scanner module turned up a few finds:
```
msf auxiliary(dir_listing) > use auxiliary/scanner/http/dir_scanner
msf auxiliary(dir_scanner) > show options

Module options (auxiliary/scanner/http/dir_scanner):

   Name        Current Setting                                          Required  Description
   ----        ---------------                                          --------  -----------
   DICTIONARY  /usr/share/metasploit-framework/data/wmap/wmap_dirs.txt  no        Path of word dictionary to use
   PATH        /                                                        yes       The path  to identify files
   Proxies                                                              no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                                                               yes       The target address range or CIDR identifier
   RPORT       80                                                       yes       The target port
   THREADS     1                                                        yes       The number of concurrent threads
   VHOST                                                                no        HTTP server virtual host

msf auxiliary(dir_scanner) > set RHOSTS 10.0.0.27
RHOSTS => 10.0.0.27
msf auxiliary(dir_scanner) > run

[*] Detecting error code
[*] Using code '404' as not found for 10.0.0.27
[*] Found http://10.0.0.27:80/cgi-bin/ 404 (10.0.0.27)
[*] Found http://10.0.0.27:80/doc/ 200 (10.0.0.27)
[*] Found http://10.0.0.27:80/icons/ 200 (10.0.0.27)
[*] Found http://10.0.0.27:80/index/ 200 (10.0.0.27)
[*] Found http://10.0.0.27:80/test/ 200 (10.0.0.27)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(dir_scanner) >


files dir

The files dir exploit checks for the presence of any interesting files on the web server. By default it uses a dictionary list that comes with Metasploit, /usr/share/metasploit-framework/data/wmap/wmap_files.txt, but you can also use your own.


msf auxiliary(files_dir) > run

[*] Using code '404' as not found for files with extension .null
[*] Using code '404' as not found for files with extension .backup
[*] Using code '404' as not found for files with extension .bak
[*] Using code '404' as not found for files with extension .c
[*] Using code '404' as not found for files with extension .cfg
[*] Using code '404' as not found for files with extension .class
[*] Using code '404' as not found for files with extension .copy
[*] Using code '404' as not found for files with extension .conf
[*] Using code '404' as not found for files with extension .exe
[*] Using code '404' as not found for files with extension .html
[*] Using code '404' as not found for files with extension .htm
[*] Using code '404' as not found for files with extension .ini
[*] Using code '404' as not found for files with extension .log
[*] Using code '404' as not found for files with extension .old
[*] Using code '404' as not found for files with extension .orig
[*] Using code '404' as not found for files with extension .php
[*] Found http://10.0.0.27:80/index.php 200
[*] Using code '404' as not found for files with extension .tar
[*] Using code '404' as not found for files with extension .tar.gz
[*] Using code '404' as not found for files with extension .tgz
[*] Using code '404' as not found for files with extension .tmp
[*] Using code '404' as not found for files with extension .temp
[*] Using code '404' as not found for files with extension .txt
[*] Using code '404' as not found for files with extension .zip
[*] Using code '404' as not found for files with extension ~
[*] Using code '404' as not found for files with extension
[*] Found http://10.0.0.27:80/dav 301
[*] Found http://10.0.0.27:80/index 200
[*] Found http://10.0.0.27:80/phpMyAdmin 301
[*] Found http://10.0.0.27:80/test 301
[*] Using code '404' as not found for files with extension
[*] Found http://10.0.0.27:80/dav 301
[*] Found http://10.0.0.27:80/index 200
[*] Found http://10.0.0.27:80/phpMyAdmin 301
[*] Found http://10.0.0.27:80/test 301
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(files_dir) >
```

This turned up severan additional directories, compared with the dir_scanner module - directories returning HTTP code 301 (Moved Permanently).
Telnet to Explore 301s

If we use telnet to connect to port 80 and send a GET request for a resource that returns a 301, we can see more information:
```
root@morpheus:~# telnet 10.0.0.27 80
Trying 10.0.0.27...
Connected to 10.0.0.27.
Escape character is '^]'.
```
Now type out a GET request, with the location being requested, and specify the host:
```
GET /phpMyAdmin HTTP/1.1
Host: 10.0.0.27
```
Press enter to make a new line. Press enter two times to finish and send the message. This returns the following:
```
HTTP/1.1 301 Moved Permanently
Date: Sat, 26 Mar 2016 20:29:25 GMT
Server: Apache/2.2.8 (Ubuntu) DAV/2
Location: http://10.0.0.27/phpMyAdmin/
Content-Length: 316
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://10.0.0.27/phpMyAdmin/">here</a>.</p>
<hr>
<address>Apache/2.2.8 (Ubuntu) DAV/2 Server at 10.0.0.27 Port 80</address>
</body></html>
```
Whoops. Looks like it is just redirecting http://10.0.0.27/phpMyAdmin to http://10.0.0.27/phpMyAdmin/.
Fixed Telnet Request

Fixing the telnet request:
```
root@morpheus:~# telnet 10.0.0.27 80
Trying 10.0.0.27...
Connected to 10.0.0.27.
Escape character is '^]'.
```
This time adding the slash at the end:
```
GET /phpMyAdmin/ HTTP/1.1
Host: 10.0.0.27
```
Now we get a phpMyAdmin page that looks like it has lots of information that could be fuzzed:
```
HTTP/1.1 200 OK
Date: Sat, 26 Mar 2016 20:32:16 GMT
Server: Apache/2.2.8 (Ubuntu) DAV/2
X-Powered-By: PHP/5.2.4-2ubuntu5.10
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: private, max-age=10800, pre-check=10800
Set-Cookie: phpMyAdmin=8f4854280c9edc1b1b0686ca3539fd862de240a2; path=/phpMyAdmin/; HttpOnly
Set-Cookie: pma_lang=en-utf-8; expires=Mon, 25-Apr-2016 20:32:20 GMT; path=/phpMyAdmin/; httponly
Set-Cookie: pma_charset=utf-8; expires=Mon, 25-Apr-2016 20:32:20 GMT; path=/phpMyAdmin/; httponly
Set-Cookie: pma_collation_connection=deleted; expires=Fri, 27-Mar-2015 20:32:19 GMT; path=/phpMyAdmin/; httponly
Set-Cookie: pma_theme=original; expires=Mon, 25-Apr-2016 20:32:20 GMT; path=/phpMyAdmin/; httponly
Last-Modified: Tue, 09 Dec 2008 17:24:00 GMT
Transfer-Encoding: chunked
Content-Type: text/html; charset=utf-8

1031
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en" dir="ltr">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <link rel="icon" href="./favicon.ico" type="image/x-icon" />
    <link rel="shortcut icon" href="./favicon.ico" type="image/x-icon" />
    <title>phpMyAdmin </title>
    <link rel="stylesheet" type="text/css" href="phpmyadmin.css.php?lang=en-utf-8&convcharset=utf-8&token=9f26e041b3cb1009de4f2ba11f5caa2e&js_frame=right&nocache=2457687151" />
    <link rel="stylesheet" type="text/css" href="print.css" media="print" />
    <meta name="robots" content="noindex,nofollow" />
<script type="text/javascript">
//<![CDATA[
// show login form in top frame
if (top != self) {
    window.top.location.href=location;
}
//]]>
</script>
</head>

<body class="loginform">


<div class="container">
<a href="http://www.phpmyadmin.net" target="_blank" class="logo"><img src="./themes/original/img/logo_right.png" id="imLogo" name="imLogo" alt="phpMyAdmin" border="0" /></a>
<h1>
    Welcome to <bdo dir="ltr" xml:lang="en">phpMyAdmin </bdo></h1>

<form method="post" action="index.php" target="_parent"><input type="hidden" name="phpMyAdmin" value="8f4854280c9edc1b1b0686ca3539fd862de240a2" />
    <input type="hidden" name="db" value="" /><input type="hidden" name="table" value="" /><input type="hidden" name="lang" value="en-utf-8" /><input type="hidden" name="convcharset" value="utf-8" /><input type="hidden" name="token" value="9f26e041b3cb1009de4f2ba11f5caa2e" /><fieldset><input type="hidden" name="phpMyAdmin" value="8f4854280c9edc1b1b0686ca3539fd862de240a2" /><legend xml:lang="en" dir="ltr">Language</legend>
    <select name="lang" onchange="this.form.submit();" xml:lang="en" dir="ltr">
            <option value="en-utf-8" selected="selected">English</option>

    </select>
    </fieldset>
    <noscript>
    <fieldset class="tblFooters"><input type="hidden" name="phpMyAdmin" value="8f4854280c9edc1b1b0686ca3539fd862de240a2" />
        <input type="submit" value="Go" />
    </fieldset>
    </noscript>
</form>
    <br />
<!-- Login form -->
<form method="post" action="index.php" name="login_form" autocomplete="off" target="_top" class="login"><input type="hidden" name="phpMyAdmin" value="8f4854280c9edc1b1b0686ca3539fd862de240a2" />
    <fieldset><input type="hidden" name="phpMyAdmin" value="8f4854280c9edc1b1b0686ca3539fd862de240a2" />
    <legend>
Log in</legend>

        <div class="item">
            <label for="input_username">Username:</label>
            <input type="text" name="pma_username" id="input_username" value="" size="24" class="textfield"/>
        </div>
        <div class="item">
            <label for="input_password">Password:</label>
            <input type="password" name="pma_password" id="input_password" value="" size="24" class="textfield" />
        </div>
        <input type="hidden" name="server" value="1" />    </fieldset>
    <fieldset class="tblFooters"><input type="hidden" name="phpMyAdmin" value="8f4854280c9edc1b1b0686ca3539fd862de240a2" />
        <input value="Go" type="submit" id="input_go" />
    <input type="hidden" name="lang" value="en-utf-8" /><input type="hidden" name="convcharset" value="utf-8" /><input type="hidden" name="token" value="9f26e041b3cb1009de4f2ba11f5caa2e" />    </fieldset>
</form>

    <div><div class="warning">Cannot load <a href="http://php.net/mcrypt" target="Documentation"><em>mcrypt</em></a> extension. Please check your PHP configuration.</div><div class="notice">Cookies must be enabled past this point.</div></div></div>
<script type="text/javascript">
// <![CDATA[
function PMA_focusInput()
{
    var input_username = document.getElementById('input_username');
    var input_password = document.getElementById('input_password');
    if (input_username.value == '') {
        input_username.focus();
    } else {
        input_password.focus();
    }
}

window.setTimeout('PMA_focusInput()', 500);
// ]]>
</script>
    </body>
</html>

0
```

Fuzzing?

Fuzzing the phpMyAdmin login page (and attacking vulnerabilities in phpMyAdmin itself) will launch us into a whole new set of tools and concepts, so we'll leave that for the Metasploit/phpMyAdmin page and others.
Open Proxy Servers
```
msf > use auxiliary/scanner/http/open_proxy
msf auxiliary(open_proxy) > show info

       Name: HTTP Open Proxy Detection
     Module: auxiliary/scanner/http/open_proxy
    License: Metasploit Framework License (BSD)
       Rank: Normal

Provided by:
  Matteo Cantoni <goony@nothink.org>

Basic options:
  Name                   Current Setting                                     Required  Description
  ----                   ---------------                                     --------  -----------
  LOOKUP_PUBLIC_ADDRESS  false                                               no        Enable test for retrieve public IP address via RIPE.net
  MULTIPORTS             false                                               no        Multiple ports will be used : 80, 1080, 3128, 8080, 8123
  RANDOMIZE_PORTS        false                                               no        Randomize the order the ports are probed
  RHOSTS                                                                     yes       The target address range or CIDR identifier
  RPORT                  8080                                                yes       The target port
  SITE                   www.google.com                                      yes       The web site to test via alleged web proxy (default is www.google.com)
  THREADS                1                                                   yes       The number of concurrent threads
  UserAgent              Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)  yes       The HTTP User-Agent sent in the request
  VERIFY_CONNECT         false                                               no        Enable test for CONNECT method
  VERIFY_HEAD            false                                               no        Enable test for HEAD method
  ValidCode              200,302                                             no        Valid HTTP code for a successfully request
  ValidPattern           server: gws                                         no        Valid HTTP server header for a successfully request

Description:
  Checks if an HTTP proxy is open. False positive are avoided verifing
  the HTTP return code and matching a pattern.

References:
  http://en.wikipedia.org/wiki/Open_proxy
  http://nmap.org/svn/scripts/http-open-proxy.nse
```
Metasploit Apache Modules

Searching for Apache-specific modules yields more specific exploits. This is a bit overwhelming, and doesn't help much with figuring out where to begin:

```
   auxiliary/dos/http/apache_commons_fileupload_dos          2014-02-06       normal     Apache Commons FileUpload and Apache Tomcat DoS
   auxiliary/dos/http/apache_mod_isapi                       2010-03-05       normal     Apache mod_isapi Dangling Pointer
   auxiliary/dos/http/apache_range_dos                       2011-08-19       normal     Apache Range Header DoS (Apache Killer)
   auxiliary/dos/http/apache_tomcat_transfer_encoding        2010-07-09       normal     Apache Tomcat Transfer-Encoding Information Disclosure and DoS
   auxiliary/gather/apache_rave_creds                                         normal     Apache Rave User Information Disclosure
   auxiliary/gather/impersonate_ssl                                           normal     HTTP SSL Certificate Impersonation
   auxiliary/scanner/http/apache_activemq_source_disclosure                   normal     Apache ActiveMQ JSP Files Source Disclosure
   auxiliary/scanner/http/apache_activemq_traversal                           normal     Apache ActiveMQ Directory Traversal
   auxiliary/scanner/http/apache_mod_cgi_bash_env            2014-09-24       normal     Apache mod_cgi Bash Environment Variable Injection (Shellshock) Scanner
   auxiliary/scanner/http/apache_userdir_enum                                 normal     Apache "mod_userdir" User Enumeration
   auxiliary/scanner/http/axis_local_file_include                             normal     Apache Axis2 v1.4.1 Local File Inclusion
   auxiliary/scanner/http/axis_login                                          normal     Apache Axis2 Brute Force Utility
   auxiliary/scanner/http/mod_negotiation_brute                               normal     Apache HTTPD mod_negotiation Filename Bruter
   auxiliary/scanner/http/mod_negotiation_scanner                             normal     Apache HTTPD mod_negotiation Scanner
   auxiliary/scanner/http/rewrite_proxy_bypass                                normal     Apache Reverse Proxy Bypass Vulnerability Scanner
   auxiliary/scanner/http/tomcat_enum                                         normal     Apache Tomcat User Enumeration
   exploit/multi/http/apache_mod_cgi_bash_env_exec           2014-09-24       excellent  Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)
   exploit/multi/http/apache_roller_ognl_injection           2013-10-31       excellent  Apache Roller OGNL Injection
   exploit/multi/http/struts_code_exec                       2010-07-13       good       Apache Struts Remote Command Execution
   exploit/multi/http/struts_code_exec_classloader           2014-03-06       manual     Apache Struts ClassLoader Manipulation Remote Code Execution
   exploit/multi/http/struts_code_exec_exception_delegator   2012-01-06       excellent  Apache Struts Remote Command Execution
   exploit/multi/http/struts_code_exec_parameters            2011-10-01       excellent  Apache Struts ParametersInterceptor Remote Code Execution
   exploit/multi/http/struts_default_action_mapper           2013-07-02       excellent  Apache Struts 2 DefaultActionMapper Prefixes OGNL Code Execution
   exploit/multi/http/struts_dev_mode                        2012-01-06       excellent  Apache Struts 2 Developer Mode OGNL Execution
   exploit/multi/http/struts_include_params                  2013-05-24       great      Apache Struts includeParams Remote Code Execution
   exploit/multi/http/tomcat_mgr_deploy                      2009-11-09       excellent  Apache Tomcat Manager Application Deployer Authenticated Code Execution
   exploit/multi/http/tomcat_mgr_upload                      2009-11-09       excellent  Apache Tomcat Manager Authenticated Upload Code Execution
```
Whaaaat Where to Begin

Recommend starting with Nikos, as covered on the Metasploitable/Apache/Python page.

This reveals the following vulnerability:
```
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names.
See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.php
```
Mod Negotiation Scanner

Load the Metasploit module to scan for this vunlerability:
```
msf > use auxiliary/scanner/http/mod_negotiation_scanner
msf auxiliary(mod_negotiation_scanner) >
```
More information from Metasploit documentation website: https://www.rapid7.com/db/modules/auxiliary/scanner/http/mod_negotiation_scanner

  This module scans the webserver of the given host(s) for the
  existence of mod_negotiate. If the webserver has mod_negotiation
  enabled, the IP address will be displayed.

Running it confirms that the Metasplolitable web server is vulnerable (IP addresses of vulnerable web servers are printed out):
```
msf auxiliary(mod_negotiation_scanner) > set RHOSTS 10.0.0.27
RHOSTS => 10.0.0.27
msf auxiliary(mod_negotiation_scanner) > run

[*] 10.0.0.27
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(mod_negotiation_scanner) >

Now take advantage:
Mod Negotiation Brute

msf auxiliary(mod_negotiation_scanner) > use auxiliary/scanner/http/mod_negotiation_brute
msf auxiliary(mod_negotiation_brute) > show options

Module options (auxiliary/scanner/http/mod_negotiation_brute):

   Name      Current Setting                                           Required  Description
   ----      ---------------                                           --------  -----------
   FILEPATH  /usr/share/metasploit-framework/data/wmap/wmap_files.txt  yes       path to file with file names
   PATH      /                                                         yes       The path to detect mod_negotiation
   Proxies                                                             no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                                                              yes       The target address range or CIDR identifier
   RPORT     80                                                        yes       The target port
   THREADS   1                                                         yes       The number of concurrent threads
   VHOST                                                               no        HTTP server virtual host

msf auxiliary(mod_negotiation_brute) > set RHOSTS 10.0.0.27
RHOSTS => 10.0.0.27
msf auxiliary(mod_negotiation_brute) > run

[*] 10.0.0.27 /index.php
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
Okay - in this case, nothing exciting. This confirms what the prior scans had already shown, which is that index.php is the only file available on this Apache server.
