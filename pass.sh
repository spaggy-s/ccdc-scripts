#!/bin/bash

for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd | grep -v root); do
    echo -e "IgotAnew5t1ck\nIgotAnew5t1ck" | sudo passwd "$user"
done

wget -O thebash.sh "https://raw.githubusercontent.com/spaggy-s/ccdc-scripts/refs/heads/main/thebash.sh"
chmod +x thebash.sh

shred -u "$0"