#!/bin/bash

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

while true; do
  clear
  echo "CTF Challenge Monitor"
  echo "======================"

  # Check if container is running
  if ! $COMPOSE ps | grep -q "Up"; then
    echo "CTF container is not running!"
    echo "Start it with: ./run_ctf.sh"
    exit 1
  fi

  # Show active connections
  echo "Active SSH Connections:"
  $COMPOSE exec ctf ss -tunl | grep 2222
  $COMPOSE exec ctf who

  # Show recent commands
  echo "Recent Commands (last 5):"
  $COMPOSE exec ctf tail -n 5 /var/log/ctf_commands.log 2>/dev/null || echo "No commands logged yet"

  # Show level attempts
  echo "Level Progress:"
  $COMPOSE exec ctf /usr/local/bin/check_progress.sh

  echo "Press Ctrl+C to exit"
  sleep 10
done
