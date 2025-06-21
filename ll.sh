

# Find users in sudo and wheel groups
root_users=()
users=()

for group_name in "sudo" "wheel"; do
    members=$(getent group "$group_name" | cut -d: -f4 | tr ',' ' ')
    for user in $members; do
        if printf "%s\n" "${root_users[@]}" | grep -q -x -F "$user"; then
            continue
        fi
        root_users+=("$user")
    done
done



# Set users list and write to list

result=$(getent passwd | awk -F: '($3 >= 1000) && ($7 != "/bin/false") && ($7 != "/usr/sbin/nologin") {print $1}')

readarray -t users <<< "$result"

cdate=""
today=$(date +%s)


for user in "${users[@]}"; do
    # Find users whose passwords are locked or dont have passwords
    status=$(passwd -S "$user" | awk '{print $2}')

    if [[ "$status" == "NP" || "$status" == "L" ]]; then
        echo "$user"
        continue
    fi

    # Set the date for the user
    cdate=$(passwd -S "$user" | awk '{print $3}' | date -d - +%s)


    # Compare the date
    if (( (today - cdate) / 86400 >= 180 )); then
        echo "$user"
    fi

done








