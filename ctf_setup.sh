#!/bin/bash

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root"
  exit 1
fi

echo "Setting up CTF environment directly on the system..."

# Create a directory for our CTF setup
mkdir -p /opt/ctf_setup
cd /opt/ctf_setup

# Install necessary packages
echo "Installing required packages..."
apt-get update && apt-get install -y \
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
  ufw

# Configure SSH
echo "Configuring SSH..."
mkdir -p /var/run/sshd
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config

# Define passwords for each level
PASSWORD_0="bandit0"
PASSWORD_1="thisshit"
PASSWORD_2="thisshitt"
PASSWORD_3="thisshittt"
PASSWORD_4="thisshitttt"
PASSWORD_5="thisshittttt"
PASSWORD_6="thisshitttttt"
PASSWORD_7="thisshittttttt"
PASSWORD_8="final_password_congrats"

# Create bandit users (0-8) with custom passwords
echo "Creating users with custom passwords..."
# bandit0 has default password
useradd -m -d /home/bandit0 -s /bin/bash bandit0
echo "bandit0:$PASSWORD_0" | chpasswd

# bandit1 through bandit8 have progressive passwords
for i in $(seq 1 8); do
  useradd -m -d /home/bandit$i -s /bin/bash bandit$i
  eval "echo \"bandit$i:\$PASSWORD_$i\"" | chpasswd
done

# Set proper permissions for home directories
chmod 700 /home/bandit*

# Level 0 (Demo)
echo "Setting up Level 0 (Demo)..."
echo "Welcome to the CTF Challenge!\n\nYour goal is to find the password for the next level.\nFor this demo level, the password for level 1 is: $PASSWORD_1\n\nTo access the next level, use:\nssh bandit1@localhost -p 2222\n" >/home/bandit0/README.txt
chown bandit0:bandit0 /home/bandit0/README.txt

# Level 1: Hidden Files
echo "Setting up Level 1: Hidden Files..."
echo "$PASSWORD_2" >/home/bandit1/.hidden_password
chmod 400 /home/bandit1/.hidden_password
chown bandit1:bandit1 /home/bandit1/.hidden_password
echo "Find the hidden file in this directory" >/home/bandit1/README.txt
chown bandit1:bandit1 /home/bandit1/README.txt

# Level 2: File Permissions and SUID
echo "Setting up Level 2: File Permissions and SUID..."
echo "$PASSWORD_3" >/home/bandit2/password
chmod 600 /home/bandit2/password
chown bandit3:bandit3 /home/bandit2/password
echo "You need to access a file owned by bandit3. Look for special permissions." >/home/bandit2/README.txt
chown bandit2:bandit2 /home/bandit2/README.txt

# Creating SUID binary for level 2
echo '#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(geteuid());
    system("cat /home/bandit2/password");
    return 0;
}' >/home/bandit2/read_password.c
gcc -o /home/bandit2/read_password /home/bandit2/read_password.c
chmod 4755 /home/bandit2/read_password
chown bandit3:bandit2 /home/bandit2/read_password

# Level 3: Scheduled Tasks
echo "Setting up Level 3: Scheduled Tasks..."
echo "* * * * * echo '$PASSWORD_4' > /tmp/password_drop && chmod 644 /tmp/password_drop && sleep 30 && rm /tmp/password_drop" >/etc/cron.d/bandit3_task
chmod 644 /etc/cron.d/bandit3_task
echo "The password appears and disappears somewhere in the system. Can you catch it?" >/home/bandit3/README.txt
chown bandit3:bandit3 /home/bandit3/README.txt

# Level 4: Network Services
echo "Setting up Level 4: Network Services..."
echo "#!/usr/bin/python3
import socket

s = socket.socket()
s.bind((\"0.0.0.0\", 54321))
s.listen(5)

while True:
    c, addr = s.accept()
    c.send(b\"Welcome to level 4!\\nPassword for level5: $PASSWORD_5\\n\")
    c.close()" >/home/bandit4/service.py
chmod +x /home/bandit4/service.py
chown bandit4:bandit4 /home/bandit4/service.py

echo "There's a service running somewhere on this machine. Can you find it?" >/home/bandit4/README.txt
chown bandit4:bandit4 /home/bandit4/README.txt

# Service startup script
echo '#!/bin/bash
su - bandit4 -c "python3 /home/bandit4/service.py &"' >/usr/local/bin/start_level4.sh
chmod +x /usr/local/bin/start_level4.sh

# Level 5: Binary Analysis
echo "Setting up Level 5: Binary Analysis..."
echo "#include <stdio.h>
#include <string.h>

int main() {
    char input[100];
    printf(\"Enter secret code: \");
    scanf(\"%s\", input);
    
    if (strcmp(input, \"7h15_15_53cr37\") == 0) {
        printf(\"Password for next level: $PASSWORD_6\\n\");
    } else {
        printf(\"Incorrect!\\n\");
    }
    return 0;
}" >/home/bandit5/password_checker.c
gcc -o /home/bandit5/checker /home/bandit5/password_checker.c
chmod 4755 /home/bandit5/checker
chown bandit6:bandit5 /home/bandit5/checker
echo "There's a binary here that might help you get to the next level." >/home/bandit5/README.txt
chown bandit5:bandit5 /home/bandit5/README.txt

# Level 6: Web Exploitation
echo "Setting up Level 6: Web Exploitation..."
mkdir -p /var/www/html/secret
echo "$PASSWORD_7" >/var/www/html/secret/passwd.txt
chmod 644 /var/www/html/secret/passwd.txt
echo '<?php
if (isset($_GET["file"])) {
    include($_GET["file"]);
} else {
    echo "Hint: This page accepts a \"file\" parameter.";
}
// The password is in /var/www/html/secret/passwd.txt
?>' >/var/www/html/level6.php
chown -R www-data:www-data /var/www/html/
echo "There's a website running locally. Try accessing http://localhost/level6.php" >/home/bandit6/README.txt
chown bandit6:bandit6 /home/bandit6/README.txt

# Level 7: Privilege Escalation
echo "Setting up Level 7: Privilege Escalation..."
echo "bandit7 ALL=(bandit8) NOPASSWD: /usr/bin/cat /home/bandit7/not_here/*" >>/etc/sudoers
mkdir -p /home/bandit7/not_here
echo "$PASSWORD_8" >/home/bandit8/.password
chmod 600 /home/bandit8/.password
chown bandit8:bandit8 /home/bandit8/.password
echo "Can you leverage sudo privileges to get the final password?" >/home/bandit7/README.txt
chown bandit7:bandit7 /home/bandit7/README.txt

# Configure services
echo "Configuring and starting services..."

# Update SSH configuration to listen on port 2222
if ! grep -q "Port 2222" /etc/ssh/sshd_config; then
  echo "Port 2222" >>/etc/ssh/sshd_config
fi

# Make sure SSH service is running
systemctl restart ssh

# Make sure Apache is running
systemctl enable apache2
systemctl restart apache2

# Make sure cron is running
systemctl enable cron
systemctl restart cron

# Start level 4 service
/usr/local/bin/start_level4.sh

# Create a systemd service to ensure level4 service starts on boot
echo "[Unit]
Description=CTF Level 4 Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/start_level4.sh
Restart=always

[Install]
WantedBy=multi-user.target" >/etc/systemd/system/ctf-level4.service

systemctl enable ctf-level4.service
systemctl start ctf-level4.service

echo -e "\nCTF setup is complete!"
echo -e "\nConnect to the first level with:"
echo "ssh bandit0@localhost -p 2222"
echo "Password: bandit0"

echo -e "\nCTF Levels:"
echo "Level 0: Demo level (Password: bandit0)"
echo "Level 1: Hidden Files (Password: thisshit)"
echo "Level 2: File Permissions and SUID (Password: thisshitt)"
echo "Level 3: Scheduled Tasks (Password: thisshittt)"
echo "Level 4: Network Services (Password: thisshitttt)"
echo "Level 5: Binary Analysis (Password: thisshittttt)"
echo "Level 6: Web Exploitation (Password: thisshitttttt)"
echo "Level 7: Privilege Escalation (Password: thisshittttttt)"
echo "Level 8: Final level (Password: final_password_congrats)"

echo -e "\nNote: All services are configured to start automatically on system boot."
echo -e "Warning: This script makes significant changes to your system. It should only be run on a dedicated CTF server."
