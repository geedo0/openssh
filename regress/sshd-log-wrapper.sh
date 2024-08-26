#!/bin/sh
timestamp="`/home/kk/workspace/Open-quantum-safe/OpenSSHv9/openssh/regress/timestamp`"
logfile="/home/kk/workspace/Open-quantum-safe/OpenSSHv9/openssh/regress/log/${timestamp}.sshd.$$.log"
rm -f /home/kk/workspace/Open-quantum-safe/OpenSSHv9/openssh/regress/sshd.log
touch $logfile
test -z "" || chown kk $logfile
ln -f -s ${logfile} /home/kk/workspace/Open-quantum-safe/OpenSSHv9/openssh/regress/sshd.log
echo "Executing: /home/kk/workspace/Open-quantum-safe/OpenSSHv9/openssh/sshd $@" log ${logfile} >>/home/kk/workspace/Open-quantum-safe/OpenSSHv9/openssh/regress/regress.log
echo "Executing: /home/kk/workspace/Open-quantum-safe/OpenSSHv9/openssh/sshd $@" >>${logfile}
exec /home/kk/workspace/Open-quantum-safe/OpenSSHv9/openssh/sshd -E${logfile} "$@"
