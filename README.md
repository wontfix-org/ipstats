# ipstats

Quickly find and sum up occurences of IPs in text

Will use a (probably too naive) regex to extract IPs from stdin or a number of files and count their occurences per IP.
Can automatically resolve IPs to hostnames (unless `-n` is passed) and can limit the output either to a maximum number
of results (`-m <n>`) or only to IPs above a certain threshold (`-t <n>`). Output is automatically sorted by number of
occurences, so the "heavy hitters" are at the bottom of the output. If there are multiple IPs per line, you can select
the desired one with the `-k` option. There are a couple more options, see `--help`. :-)

Yeah yeah, the cool kids use some overengineered logging system even for the simplest of tasks and the greybeards would
write a quick grep/awk/cut/whatever oneliner, both have their uses, but when in a pinch, this will do just fine and take
just a few seconds to run.


Show the top 20 IPs from an access log:

```
$ ipstats -m 20 /var/log/apache2/access.log
```


Show top 10 client IPs with connections in CLOSE-WAIT state
```
$ ss -tn | grep -v CLOSE-WAIT | ipstats -m 10 -k 2
```

