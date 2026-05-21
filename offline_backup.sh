#!/bin/bash
# Script to pull and save all Docker images offline for Air-Gapped deployment on Linux

COMPOSE_DIR="./docker"
EXPORT_DIR="./soc_offline_images"

echo "Checking export directory: $EXPORT_DIR"
mkdir -p "$EXPORT_DIR"

# Find all docker-compose.yml files and extract image names
echo "Extracting image names from docker-compose files..."
IMAGES=$(grep -r "^\s*image:" "$COMPOSE_DIR" | awk '{print $3}' | tr -d '"' | tr -d "'" | grep -E -v "soc-ai-agents|greenbone|tpotce" | sort | uniq)

IMAGE_COUNT=$(echo "$IMAGES" | wc -w)
echo "Found $IMAGE_COUNT unique images to download."
echo "------------------------------------------------"

for RAW_IMG in $IMAGES; do
    # Resolve Docker Compose variables like ${VERSION:-latest} to latest
    IMG=$(echo "$RAW_IMG" | sed -E 's/\$\{[^:]+:-([^}]+)\}/\1/g')
    
    echo -e "\e[36mPulling image: $IMG ...\e[0m"
    docker pull "$IMG"
    
    if [ $? -eq 0 ]; then
        # Replace slashes and colons with underscores for the filename
        SAFE_NAME=$(echo "$IMG" | sed 's/[\/:]/_/g')
        TAR_PATH="$EXPORT_DIR/${SAFE_NAME}.tar"
        
        echo -e "\e[33mSaving $IMG to $TAR_PATH ...\e[0m"
        docker save -o "$TAR_PATH" "$IMG"
        echo -e "\e[32mDone saving ${SAFE_NAME}.tar\e[0m"
    else
        echo -e "\e[31mFailed to pull $IMG\e[0m"
    fi
    echo "------------------------------------------------"
done

echo -e "\e[32mAll images processed! You can find the .tar files in $EXPORT_DIR\e[0m"
echo "To load them on your final isolated server later, run: docker load -i <filename.tar>"
