# University CTF Challenge - Documentation

This document provides a comprehensive overview of the Capture The Flag (CTF) challenge setup for your university event. The system is configured with 8 progressive levels that students must solve to advance.

## Overview

The CTF is a security-focused competition where participants ("bandit" users) must exploit various vulnerabilities to discover passwords that grant access to the next level. Each level introduces a different cybersecurity concept.

## System Requirements

- Linux-based operating system (Ubuntu 22.04 recommended)
- Root access to the system
- At least 2GB of RAM
- At least 10GB of disk space
- Network connectivity for participants

## Setup Instructions

1. Save the setup script to a file (e.g., `setup_ctf.sh`)
2. Make it executable: `chmod +x setup_ctf.sh`
3. Run with root privileges: `sudo ./setup_ctf.sh`
4. The script will output information about the setup when complete

## User Access

Participants begin at level 0 and must discover passwords to proceed to subsequent levels.

- Initial access: `ssh bandit0@hostname -p 2222` (password: `bandit0`)
- Each user must discover the password for the next level

## Level Descriptions

### Level 0: Demo Level

**Purpose**: Introduction to the CTF format
**Challenge**: Read the README.txt file to get the password for level 1
**Solution**: The README.txt file directly contains the password (`thisshit`)
**Skills**: Basic SSH and file reading

### Level 1: Hidden Files

**Purpose**: Introduce the concept of hidden files in Linux
**Challenge**: Find a hidden file in the home directory
**Solution**: Run `ls -la` to view hidden files (those starting with .), then read `.hidden_password`
**Skills**: File system navigation, command line basics

### Level 2: File Permissions and SUID

**Purpose**: Understand file permissions and SUID binaries
**Challenge**: Access a file owned by bandit3 that the current user cannot read directly
**Solution**: Execute the SUID binary `read_password` which runs with bandit3's privileges
**Skills**: Understanding Linux file permissions, SUID concept

### Level 3: Scheduled Tasks

**Purpose**: Learn about cron jobs and timing attacks
**Challenge**: Capture a password that appears and disappears in the system
**Solution**: Check running cron jobs and monitor the `/tmp/password_drop` file
**Skills**: Cron job analysis, monitoring system changes

### Level 4: Network Services

**Purpose**: Network service discovery and interaction
**Challenge**: Find and connect to a running network service
**Solution**: Use tools like `netstat -tuln` to find the service on port 54321, then connect with `nc localhost 54321`
**Skills**: Network scanning, using netcat

### Level 5: Binary Analysis

**Purpose**: Introduce reverse engineering concepts
**Challenge**: Find the secret code that makes a binary reveal the password
**Solution**: Use tools like `strings` or a debugger to find the secret code "7h15_15_53cr37"
**Skills**: Basic reverse engineering, binary analysis

### Level 6: Web Exploitation

**Purpose**: Web security and Local File Inclusion (LFI)
**Challenge**: Exploit a vulnerable web application
**Solution**: Access `http://localhost/level6.php?file=/var/www/html/secret/passwd.txt`
**Skills**: Understanding web vulnerabilities, specifically LFI

### Level 7: Privilege Escalation

**Purpose**: Learn about privilege escalation via sudo
**Challenge**: Use sudo permissions to access files beyond normal reach
**Solution**: Exploit the sudo rule to read the password file using path traversal: `sudo -u bandit8 /usr/bin/cat /home/bandit7/not_here/../../../home/bandit8/.password`
**Skills**: Privilege escalation, understanding sudo policies, path traversal

## Password Summary

| Level | Username | Password                |
| ----- | -------- | ----------------------- |
| 0     | bandit0  | bandit0                 |
| 1     | bandit1  | thisshit                |
| 2     | bandit2  | thisshitt               |
| 3     | bandit3  | thisshittt              |
| 4     | bandit4  | thisshitttt             |
| 5     | bandit5  | thisshittttt            |
| 6     | bandit6  | thisshitttttt           |
| 7     | bandit7  | thisshittttttt          |
| 8     | bandit8  | final_password_congrats |

## System Configuration

The setup script configures:

1. **SSH Server**: Running on port 2222
2. **Web Server**: Apache serving level 6 challenge
3. **Network Service**: Python socket server for level 4
4. **Cron Jobs**: For level 3 challenge
5. **User Accounts**: With appropriate permissions for each level
6. **Systemd Services**: To ensure services start on boot

## Maintenance Notes

- Participants should not have access to this documentation
- The system should be isolated from critical university infrastructure
- Monitor system resources during the event
- Consider implementing session timeouts if many participants are expected

## Troubleshooting

If participants cannot connect:

- Verify SSH is running: `systemctl status ssh`
- Check firewall settings: `ufw status`
- Ensure port 2222 is accessible

If specific levels don't work:

- Level 3: Check if cron is running: `systemctl status cron`
- Level 4: Verify the service is running: `ps aux | grep service.py`
- Level 6: Ensure Apache is running: `systemctl status apache2`

## Reset Instructions

To reset the CTF for a new event:

1. Simply run the setup script again
2. Or restore from a system snapshot if available

## Security Considerations

- This setup makes significant changes to the system
- Only deploy on a dedicated server not used for other purposes
- Consider adding firewall rules to limit access to only the university network
