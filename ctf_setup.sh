#!/bin/bash

echo "CTF Setup Script"
echo "Creating a comprehensive CTF environment with 8 progressive levels"

# Check for Docker and Docker Compose
echo "Checking prerequisites..."
if ! command -v docker &>/dev/null; then
  echo "Docker not found! Please install Docker and try again."
  exit 1
fi

if ! command -v docker-compose &>/dev/null; then
  echo "Docker Compose not found! Please install Docker Compose and try again."
  exit 1
fi

# Create a directory for our CTF setup
echo "Creating CTF environment..."
mkdir -p ctf_setup
cd ctf_setup

# Create Dockerfile
echo "Creating Dockerfile..."
cat >Dockerfile <<'EOF'
FROM ubuntu:22.04

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install necessary packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    vim \
    nano \
    python3 \
    python3-pip \
    gcc \
    make \
    git \
    netcat-openbsd \
    nmap \
    sudo \
    cron \
    php \
    apache2 \
    rsyslog \
    iproute2 \
    iputils-ping \
    curl \
    wget \
    ufw \
    steghide \
    binwalk \
    tcpdump \
    tshark \
    hexedit \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir -p /var/run/sshd
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
RUN sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
# Disable password expiration
RUN sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t-1/' /etc/login.defs

# Create all bandit users (0-10) with more users for future expansion
RUN for i in $(seq 0 10); do \
    useradd -m -d /home/bandit$i -s /bin/bash bandit$i; \
    echo "bandit$i:bandit$i" | chpasswd; \
    done

# Set proper permissions for home directories
RUN chmod 700 /home/bandit*

# Enable command logging for all users
RUN echo "export PROMPT_COMMAND='RETRN_VAL=\$?;logger -p local6.debug \"\$(who am i | cut -d\" \" -f1) [\$\$]: \$(history 1 | sed \"s/^[ ]*[0-9]\+[ ]*//\" )\"'" >> /etc/bash.bashrc
RUN echo "local6.*    /var/log/ctf_commands.log" >> /etc/rsyslog.d/ctf.conf

# Level 0 (Demo)
RUN echo "Welcome to the CTF Challenge!\n\nYour goal is to find the password for the next level.\nFor this demo level, the password for level 1 is: bacon_pancakes\n\nTo access the next level, use:\nssh bandit1@localhost -p 2222\n" > /home/bandit0/README.txt
RUN chown bandit0:bandit0 /home/bandit0/README.txt

# Level 1: Hidden Files (Intermediate)
RUN echo "turkey_sandwich" > /home/bandit1/.hidden_password
RUN chmod 400 /home/bandit1/.hidden_password
RUN chown bandit1:bandit1 /home/bandit1/.hidden_password
RUN echo "Find the hidden file in this directory. Remember that not everything is visible by default in Linux." > /home/bandit1/README.txt
RUN touch /home/bandit1/not_here.txt /home/bandit1/wrong_file.txt /home/bandit1/try_again.txt
RUN mkdir -p /home/bandit1/.secret_stuff/more_secrets
RUN echo "Getting warmer, but not here..." > /home/bandit1/.secret_stuff/hint.txt
RUN chown -R bandit1:bandit1 /home/bandit1/

# Level 2: File Permissions and SUID (Intermediate)
RUN echo "electric_keyboard" > /home/bandit2/password
RUN chmod 600 /home/bandit2/password
RUN chown bandit3:bandit3 /home/bandit2/password
RUN echo "You need to access a file owned by bandit3. Look for special permissions. Remember to check for SUID binaries." > /home/bandit2/README.txt
RUN chown bandit2:bandit2 /home/bandit2/README.txt

# Creating SUID binary for level 2
RUN echo '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n\nint main() {\n    setuid(geteuid());\n    system("cat /home/bandit2/password");\n    return 0;\n}' > /home/bandit2/read_password.c
RUN gcc -o /home/bandit2/read_password /home/bandit2/read_password.c
RUN chmod 4755 /home/bandit2/read_password
RUN chown bandit3:bandit2 /home/bandit2/read_password

# Level 3: Scheduled Tasks (Intermediate-Hard)
RUN echo "* * * * * root echo 'dancing_monkey' > /tmp/password_drop && chmod 644 /tmp/password_drop && sleep 30 && rm /tmp/password_drop" > /etc/cron.d/bandit3_task
RUN chmod 644 /etc/cron.d/bandit3_task
RUN echo "The password appears and disappears somewhere in the system every minute. Can you catch it?\nHint: Look for scheduled tasks." > /home/bandit3/README.txt
RUN chown bandit3:bandit3 /home/bandit3/README.txt

# Level 4: Network Services (Hard)
RUN echo '#!/usr/bin/python3\nimport socket\nimport time\nimport random\nimport threading\n\ndef decoy_service(port):\n    s = socket.socket()\n    s.bind((\"0.0.0.0\", port))\n    s.listen(5)\n    while True:\n        try:\n            c, addr = s.accept()\n            c.send(b\"Scanning system... Access denied.\\n\")\n            c.close()\n        except:\n            pass\n\ndef real_service():\n    s = socket.socket()\n    s.bind((\"0.0.0.0\", 54321))\n    s.listen(5)\n    while True:\n        try:\n            c, addr = s.accept()\n            c.send(b\"Welcome to the secret service!\\nPassword for level5: rubber_chicken\\n\")\n            c.close()\n        except:\n            pass\n\n# Start decoy services\nfor port in [31337, 44444, 12345]:\n    t = threading.Thread(target=decoy_service, args=(port,))\n    t.daemon = True\n    t.start()\n\n# Start real service\nreal_service()' > /home/bandit4/service.py
RUN chmod +x /home/bandit4/service.py
RUN chown bandit4:bandit4 /home/bandit4/service.py

RUN echo "There are several services running on this machine. Find the right one to get the password.\nHint: Port scanning might be useful." > /home/bandit4/README.txt
RUN chown bandit4:bandit4 /home/bandit4/README.txt

# Service startup script
RUN echo '#!/bin/bash\nsu - bandit4 -c "python3 /home/bandit4/service.py &"' > /usr/local/bin/start_level4.sh
RUN chmod +x /usr/local/bin/start_level4.sh

# Level 5: Binary Analysis (Hard)
RUN echo '#include <stdio.h>\n#include <string.h>\n#include <stdlib.h>\n#include <time.h>\n\nvoid hide_password() {\n    // This function looks important but is actually a decoy\n    char fake[] = "not_the_password";\n    printf("System secure.\\n");\n}\n\nint main() {\n    char input[100];\n    printf("Enter secret code: ");\n    scanf("%s", input);\n    \n    if (strcmp(input, "open_sesame") == 0) {\n        printf("Password for next level: flying_squirrel\\n");\n    } else {\n        printf("Incorrect!\\n");\n    }\n    return 0;\n}' > /home/bandit5/password_checker.c
RUN gcc -o /home/bandit5/checker /home/bandit5/password_checker.c
RUN strip /home/bandit5/checker
RUN chmod 4755 /home/bandit5/checker
RUN rm /home/bandit5/password_checker.c
RUN chown bandit6:bandit5 /home/bandit5/checker
RUN echo "There's a binary here that might help you get to the next level.\nHint: Sometimes you need to look inside binaries to find secrets." > /home/bandit5/README.txt
RUN chown bandit5:bandit5 /home/bandit5/README.txt

# Level 6: Web Exploitation (Hard)
RUN mkdir -p /var/www/html/secret
RUN mkdir -p /var/www/html/admin
RUN echo "flying_lemur" > /var/www/html/secret/passwd.txt
RUN chmod 644 /var/www/html/secret/passwd.txt
RUN echo '<?php\n// TODO: Remove this comment in production. The password is in /var/www/html/secret/passwd.txt\nif (isset($_GET["file"])) {\n    $file = $_GET["file"];\n    // Security check to prevent traversal\n    if (strpos($file, "..") !== false) {\n        echo "Nice try, but we block directory traversal!";\n    } else {\n        include($file);\n    }\n} else {\n    echo "<h1>Welcome to the Level 6 Web Challenge</h1>";\n    echo "<p>This page accepts a \"file\" parameter, but be careful, we have security measures in place.</p>";\n}\n?>' > /var/www/html/level6.php
RUN echo '<?php\n// Admin panel - Restricted Access\necho "<h1>Admin Panel</h1>";\necho "<p>This page is under construction.</p>";\n?>' > /var/www/html/admin/index.php
RUN chown -R www-data:www-data /var/www/html/
RUN echo "There's a website running locally. Try accessing http://localhost/level6.php\nHint: Web applications often have vulnerabilities that let you access files you shouldn't." > /home/bandit6/README.txt
RUN chown bandit6:bandit6 /home/bandit6/README.txt

# Level 7: Privilege Escalation (Hard)
RUN echo "bandit7 ALL=(bandit8) NOPASSWD: /usr/bin/cat /home/bandit7/not_here/*" >> /etc/sudoers
RUN mkdir -p /home/bandit7/not_here
RUN echo "underwater_basket" > /home/bandit8/.password
RUN chmod 600 /home/bandit8/.password
RUN chown bandit8:bandit8 /home/bandit8/.password

# Add some misdirection files
RUN echo "Try harder!" > /home/bandit7/not_here/hint.txt
RUN echo "Still not here..." > /home/bandit7/not_here/wrong.txt
RUN chmod 644 /home/bandit7/not_here/*
RUN chown bandit7:bandit7 /home/bandit7/not_here/*

RUN echo "Can you leverage sudo privileges to get the final password?\nHint: Sometimes permissions allow you to do more than what was intended." > /home/bandit7/README.txt
RUN chown bandit7:bandit7 /home/bandit7/README.txt

# Bonus Level 8: Steganography and Forensics (Expert)
RUN mkdir -p /home/bandit8/challenge
RUN echo "Congratulations on making it this far! For the final bonus challenge, find the hidden message in the image.\nPassword hint: 'weaving_dreams'" > /home/bandit8/README.txt

# Create and hide data in a PNG - simplified approach
RUN echo '#!/bin/bash\n\n# Create a simple text file with a hidden message\necho "Welcome to the final level!" > /home/bandit8/challenge/secret_message.txt\necho "You have completed all challenges!" >> /home/bandit8/challenge/secret_message.txt\necho "The master password is: golden_trophy" >> /home/bandit8/challenge/secret_message.txt\n\n# Create a hint file\necho "TRY PASSWORD: weaving_dreams" > /home/bandit8/challenge/hint.txt\n\n# Set permissions\nchmod 644 /home/bandit8/challenge/secret_message.txt\nchmod 644 /home/bandit8/challenge/hint.txt' > /usr/local/bin/create_final_challenge.sh
RUN chmod +x /usr/local/bin/create_final_challenge.sh

RUN chown -R bandit8:bandit8 /home/bandit8

# Startup script
RUN echo '#!/bin/bash\n\n# Start SSH server\n/usr/sbin/sshd\n\n# Start Apache\napache2ctl start\n\n# Start cron service\nservice cron start\n\n# Start rsyslog for command logging\nservice rsyslog start\n\n# Start level 4 service\n/usr/local/bin/start_level4.sh\n\n# Create final challenge files\n/usr/local/bin/create_final_challenge.sh\n\n# Add motd\necho "Welcome to the CTF Challenge Server! Good luck and happy hacking!" > /etc/motd\n\n# Keep container running\ntail -f /dev/null' > /usr/local/bin/startup.sh
RUN chmod +x /usr/local/bin/startup.sh

# Add scripts to view progress
RUN echo "#!/bin/bash\necho \"CTF Challenge Progress Report\"\necho \"-------------------------\"\nfor i in {0..8}; do\n  if grep -q \"bandit\$i\" /var/log/auth.log; then\n    echo \"Level \$i: Attempted\"\n  else\n    echo \"Level \$i: Not yet attempted\"\n  fi\ndone" > /usr/local/bin/check_progress.sh
RUN chmod +x /usr/local/bin/check_progress.sh

EXPOSE 2222 80

CMD ["/usr/local/bin/startup.sh"]
EOF

# Create docker-compose.yml
cat >docker-compose.yml <<'EOF'
version: '3'
services:
  ctf:
    build: .
    ports:
      - "2222:2222"
      - "8081:80"  # Changed from 8080 to 8081
    volumes:
      - ctf-logs:/var/log
    cap_add:
      - SYS_ADMIN
    restart: unless-stopped
    command: ["/usr/local/bin/startup.sh"]

volumes:
  ctf-logs:
EOF

# Create run script with progress monitoring
echo "Creating run script..."
cat >run_ctf.sh <<'EOF'
#!/bin/bash

echo "CTF Challenge Server"
echo "Starting up the CTF environment..."

# Check if the container is already running
if docker-compose ps | grep -q "ctf"; then
  echo "CTF container is already running. Stopping it first..."
  docker-compose down
fi

# Build and start the container
echo "Building and starting CTF Docker container..."
docker-compose up -d --build

# Check if container started successfully
if [ $? -ne 0 ]; then
  echo "Failed to start CTF container! Check Docker logs for details."
  exit 1
fi

# Wait for container to be fully operational
echo "Waiting for services to start..."
for i in {1..10}; do
  if docker-compose exec ctf nc -z localhost 2222 2>/dev/null; then
    echo "SSH service is up!"
    break
  fi
  if [ $i -eq 10 ]; then
    echo "SSH service failed to start! Check Docker logs for details."
    echo "You can check logs with: docker-compose logs ctf"
    exit 1
  fi
  echo -n "."
  sleep 2
done

echo "CTF server is now running!"

# Display connection information
echo "Connection Information:"
echo "Connect to the first level with:"
echo "ssh bandit0@localhost -p 2222"
echo "Password: bandit0"
echo ""
echo "Web challenges available at:"
echo "http://localhost:8080/level6.php"

echo "CTF Levels:"
echo "Level 0: Demo level (Password: bacon_pancakes)"
echo "Level 1: Hidden Files"
echo "Level 2: File Permissions and SUID"
echo "Level 3: Scheduled Tasks"
echo "Level 4: Network Services"
echo "Level 5: Binary Analysis"
echo "Level 6: Web Exploitation"
echo "Level 7: Privilege Escalation"
echo "Level 8: Steganography and Forensics (Bonus)"

echo "Admin Commands:"
echo "Check progress: docker-compose exec ctf /usr/local/bin/check_progress.sh"
echo "View logs: docker-compose logs ctf"
echo "View command history: docker-compose exec ctf cat /var/log/ctf_commands.log"
echo "Stop the CTF server: docker-compose down"

echo "Good luck and happy hacking!"
EOF

chmod +x run_ctf.sh

# Create a solution guide for organizers
echo "Creating solution guide for administrators..."
cat >admin_solutions.md <<'EOF'
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
EOF

# Create a monitoring script
echo "Creating monitoring script..."
cat >monitor_ctf.sh <<'EOF'
#!/bin/bash

while true; do
  clear
  echo "CTF Challenge Monitor"
  echo "======================"
  
  # Check if container is running
  if ! docker-compose ps | grep -q "Up"; then
    echo "CTF container is not running!"
    echo "Start it with: ./run_ctf.sh"
    exit 1
  fi
  
  # Show active connections
  echo "Active SSH Connections:"
  docker-compose exec ctf ss -tunl | grep 2222
  docker-compose exec ctf who
  
  # Show recent commands
  echo "Recent Commands (last 5):"
  docker-compose exec ctf tail -n 5 /var/log/ctf_commands.log 2>/dev/null || echo "No commands logged yet"
  
  # Show level attempts
  echo "Level Progress:"
  docker-compose exec ctf /usr/local/bin/check_progress.sh
  
  echo "Press Ctrl+C to exit"
  sleep 10
done
EOF

chmod +x monitor_ctf.sh

echo "Setup complete!"
echo "Instructions:"
echo "1. Run ./run_ctf.sh to build and start the CTF server"
echo "2. Run ./monitor_ctf.sh to monitor player progress"
echo "3. Admin solutions are available in admin_solutions.md"
echo "Make sure Docker and Docker Compose are installed on the target system."
