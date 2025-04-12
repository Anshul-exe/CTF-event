#!/bin/bash

echo "CTF Challenge Server"
echo "Starting up the CTF environment..."

# Check if Docker is installed
if ! command -v docker &>/dev/null; then
  echo "Docker not found! Please install Docker and try again."
  exit 1
fi

# Determine which Docker Compose command to use
if command -v docker-compose &> /dev/null; then
    COMPOSE="docker-compose"
elif docker compose version &> /dev/null; then
    COMPOSE="docker compose"
else
    echo "Docker Compose not found! Please install Docker Compose and try again."
    exit 1
fi

echo "Using Docker Compose command: $COMPOSE"

# Check if the container is already running
if $COMPOSE ps | grep -q "ctf"; then
  echo "CTF container is already running. Stopping it first..."
  $COMPOSE down
fi

# Build and start the container
echo "Building and starting CTF Docker container..."
$COMPOSE up -d --build

# Check if container started successfully
if [ $? -ne 0 ]; then
  echo "Failed to start CTF container! Check Docker logs for details."
  exit 1
fi

# Wait for container to be fully operational
echo "Waiting for services to start..."
for i in {1..10}; do
  if $COMPOSE exec ctf nc -z localhost 2222 2>/dev/null; then
    echo "SSH service is up!"
    break
  fi
  if [ $i -eq 10 ]; then
    echo "SSH service failed to start! Check Docker logs for details."
    echo "You can check logs with: $COMPOSE logs ctf"
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
echo "http://localhost:8081/level6.php"

echo "CTF Levels and Passwords (for admin reference):"
echo "Level 0: Demo level (initial: bandit0, next level: bacon_pancakes)"
echo "Level 1: Hidden Files (password: turkey_sandwich)"
echo "Level 2: File Permissions and SUID (password: electric_keyboard)"
echo "Level 3: Scheduled Tasks (password: dancing_monkey)"
echo "Level 4: Network Services (password: rubber_chicken)"
echo "Level 5: Binary Analysis (password: flying_squirrel)"
echo "Level 6: Web Exploitation (password: flying_lemur)"
echo "Level 7: Privilege Escalation (password: underwater_basket)"
echo "Level 8: Steganography and Forensics (password: golden_trophy)"

echo "Admin Commands:"
echo "Check progress: $COMPOSE exec ctf /usr/local/bin/check_progress.sh"
echo "View logs: $COMPOSE logs ctf"
echo "View command history: $COMPOSE exec ctf cat /var/log/ctf_commands.log"
echo "Stop the CTF server: $COMPOSE down"

echo "Good luck and happy hacking!"
