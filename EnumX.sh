#!/bin/bash

trap "echo -e '\n\e[31m[!] Exiting...\e[0m'; exit 1" SIGINT

check_sudoers() {
    echo -e "\e[1;36m\n[*] Checking sudoers file for misconfigurations...\e[0m"
    sleep 2
    
    echo -e "\e[1;36m\n[*] Checking for sudo privileges...\e[0m"
    sleep 2
    
    sudo_groups=$(getent group | grep sudo)
    sudo_group=$(echo $sudo_groups | cut -d: -f1)
    
    sudo_users=$(grep "$sudo_group" /etc/group | cut -d: -f4 | tr ',' ' ')
    
    for user in $sudo_users; do
        echo -e "\e[1;33m$user\e[0m"
    done
    
    echo -e "\e[1;36m\n[*] Checking for sudo privileges in user's home directories...\e[0m"
    sleep 2
    
    home_dirs=$(ls /home)
    
    for user in $home_dirs; do
        if [ -n "$user" ]; then
            sudo_privs=$(sudo -l -U $user)
            echo -e "\e[1;33m$sudo_privs\e[0m"
        fi
    done
}

detect_suid_sgid() {
    echo -e "\e[1;36m[*] Searching for SUID/SGID files...\e[0m"
    sleep 2
    
    echo -e "\e[1;33m\n[+] SUID files found:\n\e[0m"
    find / -type f -perm -4000 -exec ls -ld {} \; 2>/dev/null
    
    echo -e "\e[1;33m\n[+] SGID files found:\n\e[0m"
    find / -type f -perm -2000 -exec ls -ld {} \; 2>/dev/null
}

find_dangerous_files_perms() {
    echo -e "\e[1;36m\n[*] Searching for files with dangerous permissions...\e[0m"
    sleep 2
    
    echo -e "\e[1;33m\n[+] Files with global write permissions and SUID/SGID set:\n\e[0m"
    find / -type f \( -perm -4000 -o -perm -2000 \) -perm -0002 -exec ls -ld {} \; 2>/dev/null
    
    echo -e "\e[1;33m\n[+] Directories with global write permissions and no sticky bit:\n\e[0m"
    find / -type d -perm -0002 ! -perm -1000 -exec ls -ld {} \; 2>/dev/null
    
    echo -e "\e[1;33m\n[+] Files with 777 permissions:\n\e[0m"
    find / -type f -perm 0777 -exec ls -ld {} \; 2>/dev/null
    
    echo -e "\e[1;33m\n[+] Executable scripts with global write permissions:\n\e[0m"
    find / -type f \( -name '*.sh' -o -name '*.py' -o -name '*.pl' \) -perm -0002 -exec ls -ld {} \; 2>/dev/null
    
    echo -e "\e[1;33m\n[+] Files with dangerous POSIX capabilities:\n\e[0m"
    getcap -r / 2>/dev/null
    
    echo -e "\e[1;33m\n[+] Files or directories with orphaned ownership:\n\e[0m"
    find / -nouser -o -nogroup -exec ls -ld {} \; 2>/dev/null
    
    echo -e "\e[1;33m\n[+] Binaries with SGID permissions:\n\e[0m"
    find / -type f -perm -2000 -exec ls -ld {} \; 2>/dev/null
    
    echo -e "\e[1;33m\n[+] Files allowing hard or symbolic links by unprivileged users:\n\e[0m"
    find / -type f -links +1 -exec ls -ld {} \; 2>/dev/null
}

get_processes() {
    echo -e "\e[1;36m\n[*] Checking running processes for misconfigurations...\e[0m"
    sleep 2
    
    echo -e "\e[1;33m\n[+] Processes running as root:\n\e[0m"
    ps aux | grep root
    
    echo -e "\e[1;33m\n[+] Processes running as other users:\n\e[0m"
    ps aux | egrep -v 'root|USER'
    
    echo -e "\e[1;33m\n[+] Processes with open network sockets:\n\e[0m"
    netstat -tulnp
    
    echo -e "\e[1;33m\n[+] Processes with open network sockets (alternative):\n\e[0m"
    ss -tulnp
    
    echo -e "\e[1;33m\n[+] Processes with open network sockets (alternative):\n\e[0m"
    lsof -i
    
    echo -e "\e[1;33m\n[+] Processes with open network sockets (alternative):\n\e[0m"
    lsof -i -n
}

enumerate_network_config() {
    echo -e "\e[1;36m\n[*] Displaying routing table and ARP entries...\e[0m"
    route -n
    arp -a

    echo -e "\e[1;36m\n[*] Checking network interfaces and IP addresses...\e[0m"
    ip addr show
    ifconfig

    echo -e "\e[1;36m\n[*] Checking firewall rules...\e[0m"
    iptables -L -v -n
}

analyze_users_groups() {
    echo -e "\e[1;36m\n[*] Checking for valid user accounts with active shells...\e[0m"
    cat /etc/passwd | grep '/bin/bash'

    echo -e "\e[1;36m\n[*] Checking for accounts without passwords or locked accounts...\e[0m"
    cat /etc/shadow | awk -F':' '($2=="!" || $2=="*" || $2=="") {print $1}'
}

audit_services() {
    echo -e "\e[1;36m\n[*] Listing active services and their configurations...\e[0m"
    systemctl list-units --type=service --state=running

    echo -e "\e[1;36m\n[*] Checking configurations of critical services...\e[0m"
    cat /etc/ssh/sshd_config
    cat /etc/mysql/my.cnf
}

system_info() {
    echo -e "\e[1;36m\n[*] Displaying CPU and memory information...\e[0m"
    lscpu
    free -h

    echo -e "\e[1;36m\n[*] Checking mounted devices and filesystems...\e[0m"
    df -h
}

check_vulnerabilities() {
    echo -e "\e[1;36m\n[*] Checking for outdated packages...\e[0m"
    apt list --upgradable 2>/dev/null || yum check-update || dnf check-update

    echo -e "\e[1;36m\n[*] Checking for available kernel updates...\e[0m"
    uname -r && apt-cache search linux-image | grep $(uname -r)
}

enumerate_other_tools() {
    echo -e "\e[1;36m\n[*] Checking for scheduled cron jobs...\e[0m"
    crontab -l
    ls -la /etc/cron.* /etc/crontab /var/spool/cron

    echo -e "\e[1;36m\n[*] Searching for custom init scripts...\e[0m"
    find /etc/rc*.d /etc/init.d /lib/systemd/system -type f -perm -u+x
}

automate_kernel_exploits() {
    kernel_version=$(uname -r | sed 's/-.*$//')
    echo -e "\e[1;95m\n[*] Kernel version: \e[0m$kernel_version"
    echo -e "\e[1;36m\n[*] Searching for kernel exploits (with searchsploit [ExploitDB])...\e[0m"
    sleep 2
    
    exploits=$(searchsploit linux kernel $kernel_version)
    echo -e "\e[1;33m$exploits\e[0m"
    
    echo -e "\e[1;36m\n[*] Using LES (Linux Exploit Suggester) to find and suggest kernel exploits...\e[0m"
    sleep 1
    curl -sSL 'https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh' | bash -s -- -f -k $kernel_version
}

clear
echo -e "\e[1;32m================Linux Privilege Escalation Enumerator================\n\e[0m"
check_sudoers
detect_suid_sgid
find_dangerous_files_perms
get_processes
enumerate_network_config
analyze_users_groups
audit_services
system_info
check_vulnerabilities
enumerate_other_tools
automate_kernel_exploits
