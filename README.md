# lfcs


## bash scripts
Run code to create and perform bash script:
```
echo who > myscript
echo ls >> muscript
chmod +x myscript
./myscript
```
Bash script
```
#!/bin/bash

# Syntax check
if [[ $# != 1 || $1 == "-h" ]]; then
  echo "Usage: $0 /etc/passwd"
  exit 1
fi

# Read command line argument in to a variable
file=$1

parse_promt() {
  until [[ "${answer}" =~ yes|no ]] ; do
    echo "Do you wish to parse ${file} (yes/no)"
    read answer
  done
  if [[ ${answer} =~ no ]]; then
    echo "Exitting..."
    exit 0
  fi
}

parse_promt

# Example line that we are parsing
# puppet:x:52:52:Puppet:/var/lib/puppet:/sbin/nologin

# Sort the file by UID
# Loop through each line amd match desired fields
sort -t ':' -k 3 -n $file | while read -r line; do
  # Obtain the user name, UID and homedir by parsing the line with cut
  user=$(echo $line | cut -f '1' -d ':')
  uid=$(echo $line | cut -f '3' -d ':')
  homedir=$(echo $line | cut -f '6' -d ':')
  echo "User ${user} has UID ${uid} and home directory ${homedir}"
  
  # use and if statement and a regex to print whether the user has a UID of at least 3 digit
  if [[ $uid =~ [0-9]{3} ]]; then echo "  This user has a UID with at least 3 digits!"; fi
done
```
Check kernel version
```
uname
```
Globbing
```
ls a*
ls ca[bt]
ls ca[b-t]
ls [a-d]??*
```
GREP
```
egrep ^r /etc/passwd
egrep h$ /etc/passwd
egrep '[false|bash]$' /etc/passwd
egrep ^r.*bash$ /etc/passwd
```
CP to current directory
```
cp /etc/hosts .
```
Create hard and soft link and check ids
```
sudo ln /etc/hosts myhost
sudo ln -s /etc/hosts myhosty
ls -il
```
Find 
```
find /etc -names hosts
find /etc -names "*hosts*"
find /etc -user ildar
find /etc -user ildar 2>/dev/null
find -mmin -1
```
Find + action
```
find /etc -name "*hosts*" -exec cp {} . \; 2>/dev/null
find /etc -size +100k 2>/dev/null 
```
Find contents
```
sudo grep ildarr /var/* 2>/dev/null
sudo grep -l ildarr /var/* 2>/dev/null
find /etc -exec grep -l ildarr {} \; 2>/dev/null
```
Vi
```
i - Go to input mode 
ESC - Go to command mode
v - to select text
d, y, p - to delete, to yank, to paste
u - undo
ctrl+R - redo
g - go to the top
G - go to the bottom 
/sometext - serch for the "some text". type n to repeat
:300 - got to line 300
dd - to delete the current line
x - to delete the current character
```
Dealing with less
```
ls -l | less
```
First and list lines
```
head -n 5 /etc/hosts
tail -n 5 /etc/hosts
head -n 4 /etc/hosts | tail -n 1
```
Check log in real-time
```
tail -f /var/log/messages
```
Grep
```
grep student * 2>/dev/null
grep -l student * 2>/dev/null # only names
grep -lR student * 2>/dev/null # only name recursive
grep -ilR student * 2>/dev/null # only name recursive case no matter
ps aux | grep cron | grep -v grep
man -k user | egrep '1|8'
```
Cut
```
cut -d : -f 1 /etc/passwd | sort | tr [:lower:] [:upper:]
```
AWK
```
awk -F : '{print $1}' /etc/passwd
```
## Users
Add users and groups
```
useradd # centos
adduser # ubuntu
groupadd
```
Manage users
```
grep ildar /etc/passwd 					# find user ildar
grep ^ildar /etc/group 					# find group ildar
sudo grep ^ildar /etc/shadow 			# show password hash
w 										# active users
usermod
usermod -aG sales anna
userdel -R # del home directory also
echo password | passwd --stdin brenda
useradd -g account -G users anna
```
User creation default
```
useradd -D
vi /etc/defaults/useradd
vi /etc/login.defs
ls -la /etc/skel
passwd -S linds
```
Security
```
vi /etc/security/limits.conf
```
## Permissions
Change group and user on the file
```
chgrp accountGroup accountFile # change group on file
chown anndUser accountFile # change owner on file
chown lindaUser.salesGroup salesFile # change owner and group on file
```
Change permissions
```
chmod g+w account # add write permission on account file
```
Access control list
```
setfacl -R -m g:sales:rx account # set permission for sales for existing files
ls -l
getfacl account
setfacl -m d:g:sales:rx account # set permission for sales for files created in a future
```
Attributes
```
chattr +i file1 
lsattr
```
## Quota
Turn on quota in fstab
```
vi /etc/fstab # add ursquota and grpquota 
```
Check quota
```
quotacheck -mavug
ls -l # aquota.group and aquota.user 
quota -vu laura # check quota for user
quotaon -a # to run quota
edquota -u laura
su - laura
dd if=/dev/zero of=/home/laura/bigfile bs=1M count=3 # try to copu 3Mb file
```
Find files with specific permission
```
find . -perm 0600 -exec ls -l {} \; 
find / -perm /4000 -exec ls -l {} \;
```

##  IPs
Add IP address
```
ip address add dev eth0 10.0.0.10 # add ip
ping 10.0.0.10 # check ip
```
centOS
```
cat /etc/redhat-release
nmtui # the easiest utility
nmcli # the flexiest utility
rpm -qa | grep bash-completion # check package
vim /etc/sysconfig/network-scripts/ifcfg-eth0 # setup config for device
```
Ubuntu
```
nano /etc/network/interfaces
```
## SSH
Config SSH and permit root login
```
vi /etc/ssh/sshd_config # PermitRootLogin no
```
Check status 
```
systemctl status ssh # centos
sudo service ssh status # ubuntu
```
Connecting using key
```
ssh-keygen
ssh-copy-id 10.211.55.6
```
Copy files
```
scp t.t 10.211.55.6:/tmp
```
Sync
```
rsync -avz /tmp 10.211.55.6:/tmp
```
## Firewall
on centos
```
firewall-cmd --list-all
firewall-cmd --get-services
ls /usr/lib/firewalld/services/ 
firewall-cmd --add-service samba
firewall-cmd --add-service samba --permanent
firewall-cmd --add-port 4000-4005/tcp --permanent
firewall-cmd --reload
firewall-cmd --remove-port 4000-4005/tcp --permanent
firewall-cmd --reload
```
on ubuntu
```
sudo ufw enable
sudo ufw status
sudo ufw allow ssh
sudo ufw reject out ssh
sudo ufw delete reject out ssh
sudo ufw deny proto tcp from 192.168.4.245 to any port 22 # 22/tcp DENY 192.168.4.245
sudo ufw reset
sudo ufw app list
sudo ufw app info OpenSSH
sudo ufw logging on
```
IPTABLES centos
```
systemctl stop firewalld
iptables -L
iptables -P INPUT DROP  # DO NOT RUN ON REMOTE
iptables -P OUTPUT DROP # DO NOT RUN ON REMOTE
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -L
iptables -L -v
iptables -A INPUT -p tcp --dport 22 -j ACCEPT						# ENABLE SSH INCOMING
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT	# ENABLE SSH INCOMING
iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT						# ENABLE SSH OUTCOMING
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT	# ENABLE SSH OUTCOMING
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT						# ENABLE WEB
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT						# ENABLE WEB
iptables-save
iptables-save > /etc/sysconfig/iptables
systemctl disable firewalld
yum search iptables
yum install iptables-services
systemctl status iptables
systemctl enable iptables
iptables -A INPUT -p icmp -j ACCEPT									# ENABLE PING									
iptables -A OUTPUT -p icmp -j ACCEPT								# ENABLE PING
iptables-save > /etc/sysconfig/iptables 		 					# ENABLE PING
```
## Time
Clock
```
hwclock
date
date -s 19:01:20
hwclock --systohc
hwclock --hctosys
timedatectl					# centos
```
NTP sync
```
systemctl status ntpd
systemctl enable ntpd
systemctl status ntpd
ps aux | grep ntp
vim /etc/ntp.conf 						# check fudge
ntpq -p
```
chrony sync
```
systemctl status chronyd
systemctl enable chronyd
systemctl start chronyd
ps aux | grep chrony
vim /etc/chrony.conf 					# 
chronyc sources
chronyc tracking						# check sync
iptables -A INPUT -p udp --dport 123 -j ACCEPT		 					# ENABLE SYNC
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT		 					# ENABLE SYNC
iptables-save > /etc/sysconfig/iptables		 							# ENABLE SYNC
```
## JOBS and PROCESSES
Work with shell jobs
```
sleep 600
crtl+z 		# send to background
sleep 700 	# run in background
jobs 		# check jobs in background
fg 			# bring back last job to foreground
fg 1		# bring back 1st job to foreground
```
Process
```
pstree -h
top
dd if=/dev/zero of=/dev/null & 			# run 3 times
ps aux| less
ps aux| grep sshd
ps -ef | less							# with parents
ps -e -o pid,args --forest | less 		# with tree
ps aux --sort pmem 						# sort by process memory
```
Process priority
```
# type r in top, select PID, setup NICE (negative to add piority, positive to reduce priority) 
nice --help
nice -n 5 dd if=/dev/zero of=/dev/null &
renice -n 5 7610
```
Signals
```
man 7 signal
#type k in top (select 15 or 9)
ps aux | grep dd
kill 7610
killall dd
killall -9 dd 
dd if=/dev/zero of=/dev/null &
dd if=/dev/zero of=/dev/null &
pidof dd
kill $(pidof dd)
```
## Sources 
Extract tar
```
tar xvf filename -C destination 	# extract
tar tvf filename | less 			# check content
tar cxvf filename /etc/				# create compressed tar
```
Libraries
```
ldd /usr/bin/passwd
cat /etc/ld.so.cache
cat /etc/ld.so.conf 				# add libraries
ls /etc/ld.so.conf.d
```
Managing packages centos
```
rpm -qa 								# list of istalled packages
rpm -qa | grep http
rpm -qi perl 							# info about package
rpm -ql perl 							# list of files
rpm -qc nmap							# list of conf files
rpm -qd nmap 							# documentation
rpm -qpi filename 						# info on file
```
YUM
```
yum search nano
yum search all sealert
ls /etc/yum.repos.d/
cat /etc/yum.repos.d/CentOS-Base.repo 
yum info postgresql 
yum install nmap-frontend
yum provides */sealert
yumdownloader vsftpd
```
Managing packages on ubuntu
```
dpkg --get-selections 					# list of istalled packages
dpkg -L nano 							# files in packages
dpkg -S /usr/bin/eject 					# check which file 
dpkg -p eject 							# info about package
```
APT
```
apt
apt-get
```
## Scheduling 
Tasks. Cron and Anacron
```
cat /etc/crontab
crontab -e # edit crontab for current user
*/10 * * * 1-5 logger its weekdays # insert this - every 10 min every hour, day, month Mo-Fr 
cd /etc/cron.d dayly weekly 
cat /etc/cron.d/sysstat
cat /etc/cron.daily/logrotate 
```
Systemd
```
cd /usr/lib/systemd/system
ls *timer
ls fstrim*
systemctl status fstrim.timer
systemctl start fstrim.timer
systemctl enable fstrim.timer 
```
At
```
systemctl status atd
at 11:00
mail -s hello root < .
atq
atrm JobNumber
at now + 5 minutes
touch testfile
vim /usr/lib/systemd/system/fstrim.timer
# ctrl+d
systemctl daemon-reload
systemctl restart fstrim.timer
crontab -u laura -e
```
## Log 
Log
```
systemctl status sshd
journalctl
mkdir -p /var/log/journal
vim /etc/systemd/journald.conf 			# check Storage=auto
```
rsyslog
```
systemctl status rsyslog
ls /etc/rsyslog.d/
cat ls /etc/rsyslog.d/listen.conf
vim /etc/rsyslog.conf
# *.crit 		/var/log/critical
systemctl restart rsyslog
logger -p crit CRITICAL SITUATION
```
Logrotate
```
cat /etc/cron.daily/logrotate
vim /etc/logrotate.conf
ls /etc/logrotate.d/
vim /etc/logrotate.d/syslog
```
Addition expamples
```
vim /etc/rsyslog.conf
systemctl restart rsyslog
vim /etc/logrotate.conf # add folder with rotate rule
logger -p crit BLAH
cat /var/log/crit
```
## Kernel 
Modules
```
lsmod | less
lsmod | grep ext4
lsmod | grep cdrom
modprobe -r cdrom
mount | grep cdrom  		# check if in use
modprobe -r sr_mod  		# remove module if used
modprobe -r cdrom			# remove cdrom
lsmod | grep cdrom
modprobe cdrom
lsmod | grep cdrom
modinfo cdrom 				# check module 
modprobe cdrom autoclose=1
ls /etc/modprobe.d/
echo options cdrom autoclose=1 > /etc/modprobe.d/cdrom.conf
```
Optimization
```
ls /proc
cat /proc/partitions
cat /proc/cpuinfo
cat /proc/meminfo
ls /proc/sys
cat /proc/sys/net/ipv6/conf/all/disable_ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
vim /etc/sysctl.conf
ls /etc/sysctl.d/
echo net.ipv6.conf.all.disable_ipv6=1 > /etc/sysctl.d/ipv6.conf
lsmod | grep vfat
modprobe vfat
lsmod | grep vfat
modprobe -r vfat
lsmod | grep vfat
sysctl -a | grep forward
sysctl -a | grep ip_forward
echo 0 > /proc/sys/net/ipv4/ip_forward
sysctl -a | grep ip_forward
echo net.ipv4.ip_config=0 > /etc/sysctl.d/ip_forward.conf
```
## Boot 
GRUP
```
vim /etc/default/grub
less /boot/grub2/grub.cfg
grub2-mkconfig
grub2-mkconfig -o /boot/grub2/grub.cfg
```
Systemd
```
ls /usr/lib/systemd/				# should not be changed
ls /usr/lib/systemd/system 			# should not be changed
ls /etc/systemd/ 					# should be changed
ls /etc/systemd/system 				# should be changed
ls /run/systemd/ 					# generated dynamically 
systemctl -t help
systemctl set-property sshd.service MemoryLimit=500M
systemctl status sshd 				# check limit
cat /etc/systemd/system/sshd.service.d/50-MemoryLimit.conf
```
## Mandatory Access Control 
SELinux
```
vim /etc/sysconfig/selinux
```
## Storage 
MBR GPT Partiotnios
```
df -h
cat /proc/partitions
lsblk
fdisk /dev/sdc
fdisk -l /dev/sdc1
# create primary, create extended, create logical withing extended
partprobe
lsblk -io KNAME,TYPE,SIZE,MODEL
```
Filesystems
```
df -h
lsblk -io KNAME,TYPE,SIZE,MODEL
mkfs.ext4 --help
mkfs.ext4 -b 1024 -L myfs /dev/sdb1		# create filesystem
mount /dev/sdb1 /mnt 					# mount device
mount 									# check mounted devices
ls /mnt
touch /mnt/afile
umount /mnt
mkfs.xfs --help
mkfs.xfs -L myfsXFS /dev/sdb2			# create filesystem
mount LABEL=myfsXFS /mnt 				# mount device
mount 									# check mounted devices
mkfs.btrfs --help
mkfs.btrfs -L butter /dev/sdb3			# create filesystem
lsblk -io KNAME,TYPE,SIZE,MODEL
```
Mount filesystems
```
df -h
lsblk -io KNAME,TYPE,SIZE,MODEL
mkdir /xfs /ext4
vim /etc/fstab  						# add devices folders filesystems
mount -a
ls /xfs
ls /exf4
vim /etc/fstab  						# delete one filesystem
cp /usr/lib/systemd/system/tmp.mount /etc/systemd/system/ext4.mount
vim /etc/systemd/system/ext4.mount   	# remove Condition line, change What-Where, Options=defaults
systemctl daemon-reload
systemctl start ext4.mount
mount | grep ext4
systemctl status ext4.mount
lsblk -io KNAME,TYPE,SIZE,MODEL
```
SWAP partitions
```
df -h
gdisk /dev/sdb 
n
p
t 				# change partition type
partprobe
mkswap /dev/sdb3
free -m
swapon /dev/sdb3 
swapoff /dev/sdb3
vim /etc/fstab  						# add swap devices folders filesystems
swapon -a
free -m
lsblk -io KNAME,TYPE,SIZE,MODEL
```
Encryption 
```
fdisk /dev/sdb 							# create a partiotion
cryptsetup luksFormat /dev/sdb5
cryptsetup luksOpen /dev/sdb5 secret  	# open with name secret
ls /dev/mapper
mkfs.ext4 /dev/mapper/secret 			# format to ext4
mount /dev/mapper/secret /mnt
touch /mnt/mysecterfile
umount /mnt
vim /etc/crypttab						# add secret /dev/sdb5
lsblk -io KNAME,TYPE,SIZE,MODEL
```
Addition
```
swapon -s
```
## LVM 
Create LVM
```
df -h
gdisk /dev/sde 					# create partition Linux LVM
gdisk -l /dev/sde
lsblk
pvcreate /dev/sdc1 						# create physical volume
vgcreate vgdata /dev/sdc1 				# create volume group
lvcreate -L 1020M -n lvdata vgdata 		# create logical volume
lvs 									# logical totals
vgs 									# group total
pvs 									# pgysical totals
ls -la /dev/mapper
ls -la /dev/vgdata/
mkdir /lvmountpoint
nano /etc/fstab
mkfs.ext4 /dev/vgdata/lvdata
mount -a
```
Labeling and UUID
```
tune2fs
tune2fs -L lvdata /dev/vgdata/lvdata
mount -a
blkid
```
Resize
```
vgs
pvs
gdisk /dev/sdc 						# add partitions
partprobe
vgextend vgdata /dev/sdc2
lvextend -l +100%FREE -r /dev/vgdata/lvdata
lvreduce -L -200M -r /dev/vgnew/lvnew
df -h
```
## Web services 
httpd
```
systemctl status httpd
ls -la /var/www/html/
ls /etc/httpd/
ls /etc/httpd/conf/httpd.conf
ls /etc/httpd/conf.d/
ls /etc/httpd/conf.modules.d/
```
Virtual Hosts
```
vim /etc/httpd/conf.d/account.example.com.conf
#<VirtualHost *:80>
#ServerAdmin webmaster@account.example.com
#DocumentRoot /html/account
#ServerName account.example.com
#</VirtualHost
```
## DNS
httpd
```
