#!/bin/bash
#set all users passwords and selfdestruct
set -e

# Get a list of all users (excluding system users)
USERS=$(cut -d: -f1,3 /etc/passwd | awk -F: '$2 >= 1000 {print $1}')

# Generate a new password (you can customize this part)
NEW_PASSWORD="IgotAnew5t1ck"

# Loop through each user and set the new password
for USER in $USERS; do
    echo "$USER:$NEW_PASSWORD" | sudo chpasswd
done

echo "Passwords updated successfully!"
shred -u "${0}"