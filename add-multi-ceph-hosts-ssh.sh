#!/bin/bash

# ===== Read input from Morpheus =====
read -r -d '' JSON_INPUT <<EOF
{
    "NODES_INPUT": "<%=customOptions.nodes%>",
    "corporate_ntp": "<%=customOptions.corporate_ntp%>",
    "solution_network_ip": "<%=customOptions.solution_network_ip%>",
    "ceph_adminuser": "<%=customOptions.ceph_adminuser%>",
    "ceph_adminuser_password": "<%=customOptions.ceph_adminuser_password%>",
    "rhsub_username": "<%=customOptions.rhsub_username%>",
    "rhsub_password": "<%=customOptions.rhsub_password%>",
    "admin_host_ip" : "<%=customOptions.admin_host_ip%>",
    "admin_host_user" : "<%=customOptions.admin_host_user%>",
    "admin_host_pass" : "<%=customOptions.admin_host_pass%>"
}
EOF

# ====== Generate timestamped input file ======
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
INPUT_FILE="/tmp/ceph-orch_${TIMESTAMP}.json"
echo "$JSON_INPUT" > "$INPUT_FILE"

# ===== Extract NODES_INPUT from JSON =====
NODES_INPUT=$(echo "$JSON_INPUT" | jq -r '.NODES_INPUT')

# ===== Validate and extract IP-host map using Python =====
HOST_IP_JSON=$(NODES_INPUT="$NODES_INPUT" python3 - <<'PYEOF'
import re, json, sys, os

input_str = os.environ.get("NODES_INPUT","")

ips = re.findall(r'value:([\d.]+)', input_str)
hosts = re.findall(r'key:([\w.-]+)', input_str)

if len(ips) != len(hosts) or len(set(ips)) != len(ips) or len(set(hosts)) != len(hosts):
    print("")
    sys.exit(1)

print(json.dumps([{"Hostname": h.strip(), "Host_IP": i.strip()} for i, h in zip(ips, hosts)]))
PYEOF
)

# ===== Exit if validation failed =====
if [[ -z "$HOST_IP_JSON" ]]; then
    echo "❌ Validation failed: mismatch or duplicate in hosts/IPs"
    exit 1
fi

echo "✅ IPs and hostnames are valid."

# ===== Perform ping test =====
echo "📡 Running ping test for each IP..."
FAILED_PINGS=()

for row in $(echo "$HOST_IP_JSON" | jq -r '.[] | @base64'); do
    _jq() { echo "$row" | base64 --decode | jq -r "$1"; }
    HOST=$(_jq '.Hostname')
    IP=$(_jq '.Host_IP')

    echo -n "🔹 Pinging $IP ($HOST)... "
    if ping -c 2 -W 2 "$IP" > /dev/null 2>&1; then
        echo "✅ Reachable"
    else
        echo "❌ Unreachable"
        FAILED_PINGS+=("$IP")
    fi
done

if [[ ${#FAILED_PINGS[@]} -gt 0 ]]; then
    echo -e "\n❌ Error: Unreachable IPs:"
    printf '  - %s\n' "${FAILED_PINGS[@]}"
    exit 1
else
    echo -e "\n✅ All IPs reachable!"
fi

# ===== Prepare variables =====
admin_host_ip=$(echo "$JSON_INPUT" | jq -r '.admin_host_ip')
admin_host_user=$(echo "$JSON_INPUT" | jq -r '.admin_host_user')
admin_host_pass=$(echo "$JSON_INPUT" | jq -r '.admin_host_pass')
ceph_user=$(echo "$JSON_INPUT" | jq -r '.ceph_adminuser')
ceph_pass=$(echo "$JSON_INPUT" | jq -r '.ceph_adminuser_password')
rhn_user=$(echo "$JSON_INPUT" | jq -r '.rhsub_username')
rhn_pass=$(echo "$JSON_INPUT" | jq -r '.rhsub_password')

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null"

# ===== Update /etc/hosts on admin host =====
echo "=== Updating /etc/hosts on admin host ==="
for row in $(echo "$HOST_IP_JSON" | jq -r '.[] | @base64'); do
    _jq() { echo "$row" | base64 --decode | jq -r "$1"; }
    HOST=$(_jq '.Hostname')
    IP=$(_jq '.Host_IP')

    echo "➕ Adding entry: $IP $HOST"
    sshpass -p "$admin_host_pass" ssh $SSH_OPTS \
        ${admin_host_user}@${admin_host_ip} \
        "grep -q '^${IP} ${HOST}\$' /etc/hosts || echo '${IP} ${HOST}' | sudo tee -a /etc/hosts >/dev/null"
done

# ===== Copy SSH keys and setup ceph user =====
echo "=== Copying SSH keys and creating '${ceph_user}' user on all nodes ==="
for row in $(echo "$HOST_IP_JSON" | jq -r '.[] | @base64'); do
    _jq() { echo "$row" | base64 --decode | jq -r "$1"; }
    IP=$(_jq '.Host_IP')

    echo "🔑 Setting up SSH and user on $IP"
    sshpass -p "$admin_host_pass" ssh-copy-id $SSH_OPTS root@$IP

    sshpass -p "$admin_host_pass" ssh $SSH_OPTS root@$IP \
        "id -u ${ceph_user} >/dev/null 2>&1 || useradd -m -s /bin/bash ${ceph_user};
         echo '${ceph_user}:${ceph_pass}' | chpasswd;
         mkdir -p /home/${ceph_user}/.ssh;
         chmod 700 /home/${ceph_user}/.ssh;
         touch /home/${ceph_user}/.ssh/authorized_keys;
         chmod 600 /home/${ceph_user}/.ssh/authorized_keys;
         chown -R ${ceph_user}:${ceph_user} /home/${ceph_user}/.ssh"
done

# ===== Grant sudo to ceph-admin user =====
echo "=== Granting sudo to ${ceph_user} user ==="
for row in $(echo "$HOST_IP_JSON" | jq -r '.[] | @base64'); do
    _jq() { echo "$row" | base64 --decode | jq -r "$1"; }
    IP=$(_jq '.Host_IP')

    echo "⚙️ Configuring sudo for ${ceph_user} on $IP"
    sshpass -p "$admin_host_pass" ssh $SSH_OPTS root@$IP \
        "echo '${ceph_user} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/${ceph_user} && chmod 440 /etc/sudoers.d/${ceph_user}"
done

# ===== Register nodes to Red Hat Subscription =====
echo "=== Registering all nodes to Red Hat Subscription ==="
for row in $(echo "$HOST_IP_JSON" | jq -r '.[] | @base64'); do
    _jq() { echo "$row" | base64 --decode | jq -r "$1"; }
    IP=$(_jq '.Host_IP')

    echo "📝 Registering $IP to RHSM"
    sshpass -p "$admin_host_pass" ssh $SSH_OPTS root@$IP "
        subscription-manager unregister || true;
        subscription-manager clean;
        subscription-manager register --username=${rhn_user} --password='${rhn_pass}' --auto-attach
    "
done

echo -e "\n✅ SSH setup, user creation, sudo configuration, and subscription completed."
