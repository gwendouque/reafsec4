# Windows Command Line

Using Net user command, administrators can manage user accounts from windows command prompt. Below are some examples on how to use this command.

#### Add a domain user account:

Net user /add newuseLoginid  newuserPassword /domain

Add new user on local computer:

Net user /add newuserLoginid  newuserPassword

Advanced options to add new user account can be read in the below article.
Add new user from windows command line.
#### Disable/Lock a domain user account:
```
Net user loginid  /ACTIVE:NO /domain
```

To enable/unlock a domain user account:
```

Net user loginid /ACTIVE:YES  /domain
```

Prevent users from changing their account password:

```
Net user loginid /Passwordchg:No
```

To allow users to change their password:

```
Net user loginid /Passwordchg:Yes
```

To retrieve the settings of a user:

```
Net user username
```

```
Example:

C:\>net user techblogger
User name                    techblogger
Full Name
Comment
User's comment
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            4/21/2011 10:10 PM
Password expires             8/19/2011 10:10 PM
Password changeable          4/21/2011 10:10 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Users
Global Group memberships     *None
The command completed successfully.
```
