# stracer
parse strace log

Based on https://github.com/johnlcf/Stana

# how to use
strace -s 10240000 -f -T -t -tt -i -y -yy -e trace=all -o strace.log ./malware

python stracer.py strace.log
