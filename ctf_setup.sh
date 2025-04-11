#!/bin/bash

# Create a directory for our CTF setup
mkdir -p ctf_setup
cd ctf_setup

# Create Dockerfile
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
    ufw \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir /var/run/sshd
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
RUN sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config

# Create bandit users (0-8) - Make sure to create bandit8 as well
RUN for i in $(seq 0 8); do \
    useradd -m -d /home/bandit$i -s /bin/bash bandit$i; \
    echo "bandit$i:bandit$i" | chpasswd; \
    done

# Set proper permissions for home directories
RUN chmod 700 /home/bandit*

# Level 0 (Demo)
RUN echo "Welcome to the CTF Challenge!\n\nYour goal is to find the password for the next level.\nFor this demo level, the password for level 1 is: thisshit\n\nTo access the next level, use:\nssh bandit1@localhost -p 2222\n" > /home/bandit0/README.txt
RUN chown bandit0:bandit0 /home/bandit0/README.txt

# Level 1: Hidden Files
RUN echo "thisshitt" > /home/bandit1/.hidden_password
RUN chmod 400 /home/bandit1/.hidden_password
RUN chown bandit1:bandit1 /home/bandit1/.hidden_password
RUN echo "Find the hidden file in this directory" > /home/bandit1/README.txt
RUN chown bandit1:bandit1 /home/bandit1/README.txt

# Level 2: File Permissions and SUID
RUN echo "thisshittt" > /home/bandit2/password
RUN chmod 600 /home/bandit2/password
RUN chown bandit3:bandit3 /home/bandit2/password
RUN echo "You need to access a file owned by bandit3. Look for special permissions." > /home/bandit2/README.txt
RUN chown bandit2:bandit2 /home/bandit2/README.txt

# Creating SUID binary for level 2
RUN echo '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n\nint main() {\n    setuid(geteuid());\n    system("cat /home/bandit2/password");\n    return 0;\n}' > /home/bandit2/read_password.c
RUN gcc -o /home/bandit2/read_password /home/bandit2/read_password.c
RUN chmod 4755 /home/bandit2/read_password
RUN chown bandit3:bandit2 /home/bandit2/read_password

# Level 3: Scheduled Tasks
RUN echo "* * * * * echo 'thisshitttt' > /tmp/password_drop && chmod 644 /tmp/password_drop && sleep 30 && rm /tmp/password_drop" > /etc/cron.d/bandit3_task
RUN chmod 644 /etc/cron.d/bandit3_task
RUN echo "The password appears and disappears somewhere in the system. Can you catch it?" > /home/bandit3/README.txt
RUN chown bandit3:bandit3 /home/bandit3/README.txt

# Level 4: Network Services
RUN echo '#!/usr/bin/python3\nimport socket\n\ns = socket.socket()\ns.bind((\"0.0.0.0\", 54321))\ns.listen(5)\n\nwhile True:\n    c, addr = s.accept()\n    c.send(b\"Welcome to level 4!\\nPassword for level5: thisshittttt\\n\")\n    c.close()' > /home/bandit4/service.py
RUN chmod +x /home/bandit4/service.py
RUN chown bandit4:bandit4 /home/bandit4/service.py

RUN echo "There's a service running somewhere on this machine. Can you find it?" > /home/bandit4/README.txt
RUN chown bandit4:bandit4 /home/bandit4/README.txt

# Service startup script
RUN echo '#!/bin/bash\nsu - bandit4 -c "python3 /home/bandit4/service.py &"' > /usr/local/bin/start_level4.sh
RUN chmod +x /usr/local/bin/start_level4.sh

# Level 5: Binary Analysis
RUN echo '#include <stdio.h>\n#include <string.h>\n\nint main() {\n    char input[100];\n    printf("Enter secret code: ");\n    scanf("%s", input);\n    \n    if (strcmp(input, "7h15_15_53cr37") == 0) {\n        printf("Password for next level: thisshitttttt\\n");\n    } else {\n        printf("Incorrect!\\n");\n    }\n    return 0;\n}' > /home/bandit5/password_checker.c
RUN gcc -o /home/bandit5/checker /home/bandit5/password_checker.c
RUN chmod 4755 /home/bandit5/checker
RUN chown bandit6:bandit5 /home/bandit5/checker
RUN echo "There's a binary here that might help you get to the next level." > /home/bandit5/README.txt
RUN chown bandit5:bandit5 /home/bandit5/README.txt

# Level 6: Web Exploitation
RUN mkdir -p /var/www/html/secret
RUN echo "thisshittttttt" > /var/www/html/secret/passwd.txt
RUN chmod 644 /var/www/html/secret/passwd.txt
RUN echo '<?php\nif (isset($_GET["file"])) {\n    include($_GET["file"]);\n} else {\n    echo "Hint: This page accepts a \"file\" parameter.";\n}\n// The password is in /var/www/html/secret/passwd.txt\n?>' > /var/www/html/level6.php
RUN chown -R www-data:www-data /var/www/html/
RUN echo "There's a website running locally. Try accessing http://localhost/level6.php" > /home/bandit6/README.txt
RUN chown bandit6:bandit6 /home/bandit6/README.txt

# Level 7: Privilege Escalation
RUN echo "bandit7 ALL=(bandit8) NOPASSWD: /usr/bin/cat /home/bandit7/not_here/*" >> /etc/sudoers
RUN mkdir -p /home/bandit7/not_here
RUN echo "final_password_congrats" > /home/bandit8/.password
RUN chmod 600 /home/bandit8/.password
RUN chown bandit8:bandit8 /home/bandit8/.password
RUN echo "Can you leverage sudo privileges to get the final password?" > /home/bandit7/README.txt
RUN chown bandit7:bandit7 /home/bandit7/README.txt

# Startup script
RUN echo '#!/bin/bash\n\n# Start SSH server\n/usr/sbin/sshd\n\n# Start Apache\napache2ctl start\n\n# Start cron service\nservice cron start\n\n# Start level 4 service\n/usr/local/bin/start_level4.sh\n\n# Keep container running\ntail -f /dev/null' > /usr/local/bin/startup.sh
RUN chmod +x /usr/local/bin/startup.sh

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
      - "8080:80"
    restart: always
EOF

# Create run script
cat >run_ctf.sh <<'EOF'
#!/bin/bash

echo "Building and starting CTF Docker container..."
docker-compose up -d

echo -e "\nCTF server is now running!"
echo -e "\nConnect to the first level with:"
echo "ssh bandit0@localhost -p 2222"
echo "Password: bandit0"

echo -e "\nCTF Levels:"
echo "Level 0: Demo level"
echo "Level 1: Hidden Files"
echo "Level 2: File Permissions and SUID"
echo "Level 3: Scheduled Tasks"
echo "Level 4: Network Services"
echo "Level 5: Binary Analysis"
echo "Level 6: Web Exploitation"
echo "Level 7: Privilege Escalation"

echo -e "\nTo stop the CTF server:"
echo "docker-compose down"
EOF

chmod +x run_ctf.sh

echo "Setup complete! Run ./run_ctf.sh to start the CTF server."
