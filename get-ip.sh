#!/bin/bash

# Get the IP address of the Docker host
HOST_IP=$(ifconfig eth0 | awk '/inet /{print substr($2,1)}')

# Find the line in the Docker Compose file that sets the HOST_IP variable
LINE=$(grep -n "HOST_IP=" docker-compose.yml | cut -d: -f1)

# Replace the value of the HOST_IP variable with the current host IP
sed -i "${LINE}s/.*/    - HOST_IP=${HOST_IP}/" docker-compose.yml

# Run docker-compose up
docker-compose up -d
