Python


### Introduction

This help file will talk about python 3 as new scripts or old should be converted to python 3
reason for this is you get access to more libaries and because python 2 is on its way to being deprecated.


### Colours
```
yellow = '\033[93m'
end_colour = '\033[0m'
purple = '\033[95m'
red = '\033[91m'
green = '\033[92m'
blue = '\033[94m'
bold_text = '\033[1m'
```

### Importing Modules
```
import os
import platform
import sys
import subprocess
```
To find out what funtions are stored in a libary, open a terminal and type in python3.
Once in the python shell and have imported the module you want to use for example os type in os.
Hit tab twice you will get output like this related to that module.
```
    os.CLD_CONTINUED             os.environb
    os.CLD_DUMPED                os.errno
    os.CLD_EXITED                os.error(
    os.CLD_TRAPPED               os.execl(
    os.EX_CANTCREAT              os.execle(
    os.EX_CONFIG                 os.execlp(
    os.EX_DATAERR                os.execlpe(
    os.EX_IOERR                  os.execv(
    os.EX_NOHOST                 os.execve(
    os.EX_NOINPUT                os.execvp(
    os.EX_NOPERM                 os.execvpe(
    os.EX_NOUSER                 os.extsep
    os.EX_OK                     os.fchdir(
    os.EX_OSERR                  os.fchmod(
    os.EX_OSFILE                 os.fchown(
    os.EX_PROTOCOL               os.fdatasync(
    os.EX_SOFTWARE               os.fdopen(
    os.EX_TEMPFAIL               os.fork(
    os.EX_UNAVAILABLE            os.forkpty(
    os.EX_USAGE                  os.fpathconf(
    os.F_LOCK                    os.fsdecode(
    os.F_OK                      os.fsencode(
    os.F_TEST                    os.fstat(
    os.F_TLOCK                   os.fstatvfs(
    os.F_ULOCK                   os.fsync(
    os.MutableMapping(           os.ftruncate(
    os.NGROUPS_MAX               os.fwalk(
    os.O_ACCMODE                 os.get_exec_path(
    os.O_APPEND                  os.get_inheritable(
    os.O_ASYNC                   os.get_terminal_size(
    os.O_CLOEXEC                 os.getcwd(
    os.O_CREAT                   os.getcwdb(
    os.O_DIRECT                  os.getegid(
    os.O_DIRECTORY               os.getenv(
    os.O_DSYNC                   os.getenvb(
    os.O_EXCL                    os.geteuid(
    os.O_LARGEFILE               os.getgid(
    os.O_NDELAY                  os.getgrouplist(
    os.O_NOATIME                 os.getgroups(
    os.O_NOCTTY                  os.getloadavg(
    os.O_NOFOLLOW                os.getlogin(
    os.O_NONBLOCK                os.getpgid(
    os.O_PATH                    os.getpgrp(
    os.O_RDONLY                  os.getpid(
    os.O_RDWR                    os.getppid(
    os.O_RSYNC                   os.getpriority(
    os.O_SYNC                    os.getresgid(
    os.O_TMPFILE                 os.getresuid(
    os.O_TRUNC                   os.getsid(
    os.O_WRONLY                  os.getuid(
    os.POSIX_FADV_DONTNEED       os.getxattr(
    os.POSIX_FADV_NOREUSE        os.initgroups(
    os.POSIX_FADV_NORMAL         os.isatty(
    os.POSIX_FADV_RANDOM         os.kill(
    os.POSIX_FADV_SEQUENTIAL     os.killpg(
    os.POSIX_FADV_WILLNEED       os.lchown(
    os.PRIO_PGRP                 os.linesep
    os.PRIO_PROCESS              os.link(
    os.PRIO_USER                 os.listdir(
    os.P_ALL                     os.listxattr(
    os.P_NOWAIT                  os.lockf(
    os.P_NOWAITO                 os.lseek(
    os.P_PGID                    os.lstat(
    os.P_PID                     os.major(
    os.P_WAIT                    os.makedev(
    os.RTLD_DEEPBIND             os.makedirs(
    os.RTLD_GLOBAL               os.minor(
    os.RTLD_LAZY                 os.mkdir(
    os.RTLD_LOCAL                os.mkfifo(
    os.RTLD_NODELETE             os.mknod(
    os.RTLD_NOLOAD               os.name
    os.RTLD_NOW                  os.nice(
    os.R_OK                      os.open(
    os.SCHED_BATCH               os.openpty(
    os.SCHED_FIFO                os.pardir
    os.SCHED_IDLE                os.path
    os.SCHED_OTHER               os.pathconf(
    os.SCHED_RESET_ON_FORK       os.pathconf_names
    os.SCHED_RR                  os.pathsep
    os.SEEK_CUR                  os.pipe(
    os.SEEK_DATA                 os.pipe2(
    os.SEEK_END                  os.popen(
    os.SEEK_HOLE                 os.posix_fadvise(
    os.SEEK_SET                  os.posix_fallocate(
    os.ST_APPEND                 os.pread(
    os.ST_MANDLOCK               os.putenv(
    os.ST_NOATIME                os.pwrite(
    os.ST_NODEV                  os.read(
    os.ST_NODIRATIME             os.readlink(
    os.ST_NOEXEC                 os.readv(
    os.ST_NOSUID                 os.remove(
    os.ST_RDONLY                 os.removedirs(
    os.ST_RELATIME               os.removexattr(
    os.ST_SYNCHRONOUS            os.rename(
    os.ST_WRITE                  os.renames(
    os.TMP_MAX                   os.replace(
    os.WCONTINUED                os.rmdir(
    os.WCOREDUMP(                os.sched_get_priority_max(
    os.WEXITED                   os.sched_get_priority_min(
    os.WEXITSTATUS(              os.sched_getaffinity(
    os.WIFCONTINUED(             os.sched_getparam(
    os.WIFEXITED(                os.sched_getscheduler(
    os.WIFSIGNALED(              os.sched_param(
    os.WIFSTOPPED(               os.sched_rr_get_interval(
    os.WNOHANG                   os.sched_setaffinity(
    os.WNOWAIT                   os.sched_setparam(
    os.WSTOPPED                  os.sched_setscheduler(
    os.WSTOPSIG(                 os.sched_yield(
    os.WTERMSIG(                 os.sendfile(
    os.WUNTRACED                 os.sep
    os.W_OK                      os.set_inheritable(
    os.XATTR_CREATE              os.setegid(
    os.XATTR_REPLACE             os.seteuid(
    os.XATTR_SIZE_MAX            os.setgid(
    os.X_OK                      os.setgroups(
    os._Environ(                 os.setpgid(
    os.__all__                   os.setpgrp(
    os.__cached__                os.setpriority(
    os.__class__(                os.setregid(
    os.__delattr__(              os.setresgid(
    os.__dict__                  os.setresuid(
    os.__dir__(                  os.setreuid(
    os.__doc__                   os.setsid(
    os.__eq__(                   os.setuid(
    os.__file__                  os.setxattr(
    os.__format__(               os.spawnl(
    os.__ge__(                   os.spawnle(
    os.__getattribute__(         os.spawnlp(
    os.__gt__(                   os.spawnlpe(
    os.__hash__(                 os.spawnv(
    os.__init__(                 os.spawnve(
    os.__le__(                   os.spawnvp(
    os.__loader__                os.spawnvpe(
    os.__lt__(                   os.st
    os.__name__                  os.stat(
    os.__ne__(                   os.stat_float_times(
    os.__new__(                  os.stat_result(
    os.__package__               os.statvfs(
    os.__reduce__(               os.statvfs_result(
    os.__reduce_ex__(            os.strerror(
    os.__repr__(                 os.supports_bytes_environ
    os.__setattr__(              os.supports_dir_fd
    os.__sizeof__(               os.supports_effective_ids
    os.__spec__                  os.supports_fd
    os.__str__(                  os.supports_follow_symlinks
    os.__subclasshook__(         os.symlink(
    os._execvpe(                 os.sync(
    os._exists(                  os.sys
    os._exit(                    os.sysconf(
    os._fwalk(                   os.sysconf_names
    os._get_exports_list(        os.system(
    os._putenv(                  os.tcgetpgrp(
    os._spawnvef(                os.tcsetpgrp(
    os._unsetenv(                os.terminal_size(
    os._wrap_close(              os.times(
    os.abort(                    os.times_result(
    os.access(                   os.truncate(
    os.altsep                    os.ttyname(
    os.chdir(                    os.umask(
    os.chmod(                    os.uname(
    os.chown(                    os.uname_result(
    os.chroot(                   os.unlink(
    os.close(                    os.unsetenv(
    os.closerange(               os.urandom(
    os.confstr(                  os.utime(
    os.confstr_names             os.wait(
    os.cpu_count(                os.wait3(
    os.ctermid(                  os.wait4(
    os.curdir                    os.waitid(
    os.defpath                   os.waitid_result(
    os.device_encoding(          os.waitpid(
    os.devnull                   os.walk(
    os.dup(                      os.write(
    os.dup2(                     os.writev(
    os.environ
```

### Variables

To create a variable, you select the name you want it to be. For example, foo which is the name of the variable and you want it to
be asinged to a string of "example output" so when you combind this together you get:
```
foo = "example output"
```
Then we do this:
```
print(foo)
```

### Indentation
```
When you create functions, the code inside that function needs to be indented by 4 spaces. If you get this wrong, you will get a syntax
error saying invalid indention.
```

### Functions
```
The syntax for a function is def, you use def then name of function then ():.

    def example():
        print(foo)

Then call the function example(), which would print what we talked about in variables.
```

### User Input

Use the input command, which is followed by text in prenthises. For example, asign the input to a variable called user_input.
```
    user_input = input("Enter your name: ")
    print(user_input)
```

### If statments

Used to do condtional checks depending on what you define.
```
    def example():
    user_input = input("do you like apples?[yes|no]: ")

    if user_input == "yes":
        print("Me too")
    else:
        print("Thats too bad, they taste great")
example()
```
As you can see, we do a check to make sure that it equals yes, which if true, will output me to but if the user inputs no then the
else part of the if statment runs which outputs to bad they taste great.


### Example by Robert C
```
usage: python <script.py> <site>
example: python scrap.py http://www.ewhois.com/ebay.com/

-----------
import urllib2,sys,re

site = sys.argv[1]
list = []
response = urllib2.urlopen(site)
html = response.read()

for i in re.finditer('\<div\>([a-z0-9\.\-]+?)\s',html):
    list.append(i.groups(1)[0])
for i in sorted(set(list)):
    print i
```
