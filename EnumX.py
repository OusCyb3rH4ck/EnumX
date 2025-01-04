#!/usr/bin/env python3

from colorama import Fore, Style
import os, subprocess, re, signal, sys, time

def def_handler(sig, frame):
    print(f"\n{Fore.RED}[!] Exiting...{Style.RESET_ALL}")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def check_sudoers():
    print(f"{Style.BRIGHT}{Fore.CYAN}\n[*] Checking sudoers file for misconfigurations...\n{Style.RESET_ALL}")
    time.sleep(2)
    
    try:
        print(f"{Style.BRIGHT}{Fore.CYAN}\n[*] Checking for sudo privileges...\n{Style.RESET_ALL}")
        time.sleep(2)
        
        sudo_groups = subprocess.check_output("getent group | grep sudo", shell=True).decode()
        sudo_groups = sudo_groups.split(":")
        sudo_group = sudo_groups[0]
        
        sudo_users = subprocess.check_output(f"grep '{sudo_group}' /etc/group", shell=True).decode()
        sudo_users = sudo_users.split(":")
        sudo_users = sudo_users[3].split(",")
        
        for user in sudo_users:
            print(f"{Style.BRIGHT}{Fore.YELLOW}{user}{Style.RESET_ALL}")
        
        print(f"{Style.BRIGHT}{Fore.CYAN}\n[*] Checking for sudo privileges in user's home directories...\n{Style.RESET_ALL}")
        time.sleep(2)
        
        home_dirs = subprocess.check_output("ls /home", shell=True).decode()
        home_dirs = home_dirs.split("\n")
        
        for user in home_dirs:
            if user:
                sudo_privs = subprocess.check_output(f"sudo -l -U {user}", shell=True).decode()
                print(f"{Style.BRIGHT}{Fore.YELLOW}{sudo_privs}{Style.RESET_ALL}")
                
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[-] Error checking sudoers file: {str(e)}{Style.RESET_ALL}")

def detect_suid_sgid():
    print(f"{Style.BRIGHT}{Fore.CYAN}[*] Searching for SUID/SGID files...{Style.RESET_ALL}")
    time.sleep(2)
    
    try:
        print(f"{Style.BRIGHT}{Fore.YELLOW}\n[+] SUID files found:\n{Style.RESET_ALL}")
        os.system("find / -type f -perm -4000 -exec ls -ld {} \\; 2>/dev/null")
        
        print(f"{Style.BRIGHT}{Fore.YELLOW}\n[+] SGID files found:\n{Style.RESET_ALL}")
        os.system("find / -type f -perm -2000 -exec ls -ld {} \\; 2>/dev/null")
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[-] Error searching for SUID/SGID files: {str(e)}{Style.RESET_ALL}")

def find_dangerous_files_perms():
    print(f"{Style.BRIGHT}{Fore.CYAN}\n[*] Searching for files with dangerous permissions...\n{Style.RESET_ALL}")
    time.sleep(2)
    
    try:
        print(f"{Style.BRIGHT}{Fore.YELLOW}\n[+] Files with global write permissions and SUID/SGID set:\n{Style.RESET_ALL}")
        os.system("find / -type f \\( -perm -4000 -o -perm -2000 \\) -perm -0002 -exec ls -ld {} \\; 2>/dev/null")
        
        print(f"{Style.BRIGHT}{Fore.YELLOW}\n[+] Directories with global write permissions and no sticky bit:\n{Style.RESET_ALL}")
        os.system("find / -type d -perm -0002 ! -perm -1000 -exec ls -ld {} \\; 2>/dev/null")
        
        print(f"{Style.BRIGHT}{Fore.YELLOW}\n[+] Files with 777 permissions:\n{Style.RESET_ALL}")
        os.system("find / -type f -perm 0777 -exec ls -ld {} \\; 2>/dev/null")
        
        print(f"{Style.BRIGHT}{Fore.YELLOW}\n[+] Executable scripts with global write permissions:\n{Style.RESET_ALL}")
        os.system("find / -type f \\( -name '*.sh' -o -name '*.py' -o -name '*.pl' \\) -perm -0002 -exec ls -ld {} \\; 2>/dev/null")
        
        print(f"{Style.BRIGHT}{Fore.YELLOW}\n[+] Files with dangerous POSIX capabilities:\n{Style.RESET_ALL}")
        os.system("getcap -r / 2>/dev/null")
        
        print(f"{Style.BRIGHT}{Fore.YELLOW}\n[+] Files or directories with orphaned ownership:\n{Style.RESET_ALL}")
        os.system("find / -nouser -o -nogroup -exec ls -ld {} \\; 2>/dev/null")
        
        print(f"{Style.BRIGHT}{Fore.YELLOW}\n[+] Binaries with SGID permissions:\n{Style.RESET_ALL}")
        os.system("find / -type f -perm -2000 -exec ls -ld {} \\; 2>/dev/null")
        
        print(f"{Style.BRIGHT}{Fore.YELLOW}\n[+] Files allowing hard or symbolic links by unprivileged users:\n{Style.RESET_ALL}")
        os.system("find / -type f -links +1 -exec ls -ld {} \\; 2>/dev/null")
    
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[-] Error searching for dangerous permissions: {str(e)}{Style.RESET_ALL}")

def get_processes():
    print(f"{Style.BRIGHT}{Fore.CYAN}\n[*] Checking running processes for misconfigurations...\n{Style.RESET_ALL}")
    time.sleep(2)
    
    try:
        print(f"{Style.BRIGHT}{Fore.YELLOW}\n[+] Processes running as root:\n{Style.RESET_ALL}")
        os.system("ps aux | grep root")
        
        print(f"{Style.BRIGHT}{Fore.YELLOW}\n[+] Processes running as other users:\n{Style.RESET_ALL}")
        os.system("ps aux | egrep -v 'root|USER'")
        
        print(f"{Style.BRIGHT}{Fore.YELLOW}\n[+] Processes with open network sockets:\n{Style.RESET_ALL}")
        os.system("netstat -tulnp")
        
        print(f"{Style.BRIGHT}{Fore.YELLOW}\n[+] Processes with open network sockets (alternative):\n{Style.RESET_ALL}")
        os.system("ss -tulnp")
        
        print(f"{Style.BRIGHT}{Fore.YELLOW}\n[+] Processes with open network sockets (alternative):\n{Style.RESET_ALL}")
        os.system("lsof -i")
        
        print(f"{Style.BRIGHT}{Fore.YELLOW}\n[+] Processes with open network sockets (alternative):\n{Style.RESET_ALL}")
        os.system("lsof -i -n")
    
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[-] Error checking processes: {str(e)}{Style.RESET_ALL}")

def enumerate_network_config():
    print(f"{Style.BRIGHT}{Fore.CYAN}\n[*] Displaying routing table and ARP entries...\n{Style.RESET_ALL}")
    os.system("route -n")
    os.system("arp -a")

    print(f"{Style.BRIGHT}{Fore.CYAN}\n[*] Checking network interfaces and IP addresses...\n{Style.RESET_ALL}")
    os.system("ip addr show")
    os.system("ifconfig")

    print(f"{Style.BRIGHT}{Fore.CYAN}\n[*] Checking firewall rules...\n{Style.RESET_ALL}")
    os.system("iptables -L -v -n")

def analyze_users_groups():
    print(f"{Style.BRIGHT}{Fore.CYAN}\n[*] Checking for valid user accounts with active shells...\n{Style.RESET_ALL}")
    os.system("cat /etc/passwd | grep '/bin/bash'")

    print(f"{Style.BRIGHT}{Fore.CYAN}\n[*] Checking for accounts without passwords or locked accounts...\n{Style.RESET_ALL}")
    os.system("cat /etc/shadow | awk -F':' '($2==\"!\" || $2==\"*\" || $2==\"\") {print $1}'")

def audit_services():
    print(f"{Style.BRIGHT}{Fore.CYAN}\n[*] Listing active services and their configurations...\n{Style.RESET_ALL}")
    os.system("systemctl list-units --type=service --state=running")

    print(f"{Style.BRIGHT}{Fore.CYAN}\n[*] Checking configurations of critical services...\n{Style.RESET_ALL}")
    os.system("cat /etc/ssh/sshd_config")
    os.system("cat /etc/mysql/my.cnf")

def system_info():
    print(f"{Style.BRIGHT}{Fore.CYAN}\n[*] Displaying CPU and memory information...\n{Style.RESET_ALL}")
    os.system("lscpu")
    os.system("free -h")

    print(f"{Style.BRIGHT}{Fore.CYAN}\n[*] Checking mounted devices and filesystems...\n{Style.RESET_ALL}")
    os.system("df -h")

def check_vulnerabilities():
    print(f"{Style.BRIGHT}{Fore.CYAN}\n[*] Checking for outdated packages...\n{Style.RESET_ALL}")
    os.system("apt list --upgradable 2>/dev/null || yum check-update || dnf check-update")

    print(f"{Style.BRIGHT}{Fore.CYAN}\n[*] Checking for available kernel updates...\n{Style.RESET_ALL}")
    os.system("uname -r && apt-cache search linux-image | grep $(uname -r)")

def enumerate_other_tools():
    print(f"{Style.BRIGHT}{Fore.CYAN}\n[*] Checking for scheduled cron jobs...\n{Style.RESET_ALL}")
    os.system("crontab -l")
    os.system("ls -la /etc/cron.* /etc/crontab /var/spool/cron")

    print(f"{Style.BRIGHT}{Fore.CYAN}\n[*] Searching for custom init scripts...\n{Style.RESET_ALL}")
    os.system("find /etc/rc*.d /etc/init.d /lib/systemd/system -type f -perm -u+x")

def automate_kernel_exploits():
    kernel_version = os.uname().release
    kernel_version = re.sub(r"-.*$", "", kernel_version)
    print(f"{Style.BRIGHT}{Fore.LIGHTMAGENTA_EX}\n[*] Kernel version: {Style.RESET_ALL}{kernel_version}")
    print(f"{Style.BRIGHT}{Fore.CYAN}\n[*] Searching for kernel exploits (with searchsploit [ExploitDB])...\n{Style.RESET_ALL}")
    time.sleep(2)
    
    try:
        exploits = subprocess.check_output(f"searchsploit linux kernel {kernel_version}", shell=True).decode()
        exploits = exploits.split("\n")
        
        for exploit in exploits:
            if exploit:
                print(f"{Style.BRIGHT}{Fore.YELLOW}{exploit}{Style.RESET_ALL}")
    
        print(f"{Fore.CYAN+Style.BRIGHT}\n[*] Using LES (Linux Exploit Suggester) to find and suggest kernel exploits...{Style.RESET_ALL}")
        time.sleep(1)
        os.system("curl -sSL 'https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh' | bash -s -- -f -k " + kernel_version)
        

    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[-] Error searching for kernel exploits: {str(e)}{Style.RESET_ALL}")

if __name__ == '__main__':
    os.system("clear")
    print(f"{Style.BRIGHT}{Fore.GREEN}================Linux Privilege Escalation Enumerator================\n{Style.RESET_ALL}")
    check_sudoers()
    detect_suid_sgid()
    find_dangerous_files_perms()
    get_processes()
    enumerate_network_config()
    analyze_users_groups()
    audit_services()
    system_info()
    check_vulnerabilities()
    enumerate_other_tools()
    automate_kernel_exploits()
