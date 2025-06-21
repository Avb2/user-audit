mkdir -p ./audits
echo > "./audits/audit_$(date +%Y-%m-%d).txt"

# All users
users=()

# Find users in sudo and wheel groups
flagged_users=()



for group_name in "sudo" "wheel"; do
    members=$(sudo getent group "$group_name" | cut -d: -f4 | tr ',' ' ')
    for user in $members; do
        if printf "%s\n" "${flagged_users[@]}" | grep -q -x -F "$user"; then
            continue
        fi
           flagged_users+=("$user|Elevated Access")
    done
done



# Set users list and write to list

result=$(getent passwd 2>/dev/null | awk -F: '($3 >= 1000) && ($7 != "/bin/false") && ($7 != "/usr/sbin/nologin") {print $1}')

readarray -t users <<< "$result"

today=$(date +"%b %d %Y")
today_int=$(date +%s)


# Flag new users
for user in "${users[@]}"; do

    flagged_user_out="$user"

	home_creation=$(stat -c %W "$home_dir" 2>/dev/null)
	if [[ "$home_creation" -eq 0 ]]; then
	    flagged_user_out+="|No Creation Time"
	else
	   
	    if (( (today_int - home_creation) / 86400 < 7 )); then
	        flagged_user_out+="|New account"
	    fi
	fi


    # Find users whose passwords are locked or dont have passwords
    status=$(passwd -S "$user" 2>/dev/null | awk '{print $2}')
    

    if [[ "$status" == "NP" ]]; then
        flagged_user_out+="|No Password Set"
        
    elif [[ "$status" == "L" ]]; then
        flagged_user_out+="|Password Locked"
    fi

    # Set the date for the user
    cdate=$(passwd -S "$user" 2>/dev/null | awk '{print $3}' | date -d - +%s)


    # Compare the date
    if (( (today_int - cdate) / 86400 >= 180 )); then
        flagged_user_out+="|Old Password"
    fi


    # Check last login
    login_date=$(lastlog --user "$user" | awk 'NR==2 {print $4, $5, $6, $7, $8}')

    if [[ "$login_date" != *"$today"* ]]; then
        flagged_user_out+="|No Login Today"
    fi 

    # Check home dir disk usage
    home_dir=$(getent passwd "$user" 2>/dev/null | awk -F: '{print $6}')

    size_kb=$(sudo du -s "$home_dir" 2>/dev/null | awk '{print $1}')
    size_mb=$(( size_kb / 1024 ))

    if (( size_mb > 1024 )); then
        flagged_user_out+="|Disk Space Suspicious"
    fi

    # Check if flags added
    if [[ "$flagged_user_out" != "$user" ]]; then
        flagged_users+=("$flagged_user_out")
    fi
done


audit_file="./audits/audit_$(date +%Y-%m-%d).txt"

for flagged_user in "${flagged_users[@]}"; do
    echo "$flagged_user" >>  "$audit_file"
done



echo "Audit for $today attached" | mutt -s "Daily Audit $today" -a "$audit_file" -- bringuel.alexander@gmail.com
