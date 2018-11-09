# stracer
parse strace log

# how to use
strace -s 10240 -f -F -T -ttt -i -yyy -e trace=all –o strace.log ./malware

python stracer.py strace.log
