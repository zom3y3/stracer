# stracer
Stracer is a tool for parse strace log, and print some suspecial syscalls.

Based on https://github.com/johnlcf/Stana

# Usage
strace -s 10240000 -f -T -t -tt -i -y -yy -e trace=all -o strace.log ./malware

python stracer.py strace.log

```
************** Strace Analysiser **************
> Run log
Stats: Sucess
> Process Tree
2553 ./f7731ebf46e9547835836c2b495716aa

> Create Files
	/tmp/fileIoCR9A 	7e6bad3ee7cdeb30ee05d61c73073009	53615
> Unlink
	/tmp/fileIoCR9A
> Dns
	1.oo00oo.info
> Network
	IPv4	UDP	192.168.40.2:53
	IPv4	TCP	207.148.93.233:80

```
