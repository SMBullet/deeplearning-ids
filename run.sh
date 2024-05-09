#!/bin/bash

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Docker not found. Installing Docker..."
    # Install Docker 
    sudo apt-get update
    sudo apt-get install apt-transport-https ca-certificates curl software-properties-common
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
    sudo apt-get update
    sudo apt-get install docker-ce
    sudo usermod -aG docker ${USER}
    sudo systemctl enable docker
    sudo systemctl start docker
    echo "Docker installed successfully."
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "Docker Compose not found. Installing Docker Compose..."
    # Install Docker Compose
    sudo apt install docker-compose
fi

# Run Docker Compose in the current folder
docker-compose up -d

# Check if the containers are running
if [ $? -eq 0 ]; then
    echo "Docker containers are running."
else
    echo "Failed to start Docker containers."
fi
# install required python packages
pip3 install -r requirements.txt
# run the application

while true; do
  python3 main.py
  python3 ./AI/extract_db.py
  python3 ./AI/bin.py
done
