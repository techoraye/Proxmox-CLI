#!/bin/bash

# ==============================================================================
# PROXMOX AUTOMATION & MANAGEMENT By Techoraye
# ==============================================================================
# Based on PVE API: https://pve.proxmox.com/pve-docs/api-viewer/

# Configuration
PVE_HOST="${PVE_HOST:-}"
PVE_USER="${PVE_USER:-root@pam}"
PVE_PASS="${PVE_PASS:-}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Dependency Check
if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: 'jq' is not installed.${NC} sudo apt-get install jq"
    exit 1
fi

pause_action() {
    echo ""
    read -p "Press Enter to return to menu..."
}

get_credentials() {
    if [ -z "$PVE_HOST" ]; then
        read -p "Enter Proxmox Host IP/FQDN: " PVE_HOST
    fi
    if [ -z "$PVE_PASS" ]; then
        echo -e "${YELLOW}Note: Passwords are not echoed.${NC}"
        read -s -p "Enter Password for $PVE_USER: " PVE_PASS
        echo ""
    fi
}

authenticate() {
    echo -e "${BLUE}[-] Authenticating with $PVE_HOST...${NC}"
    RESPONSE=$(curl -s -k -d "username=$PVE_USER" --data-urlencode "password=$PVE_PASS" \
        "https://$PVE_HOST:8006/api2/json/access/ticket")

    TICKET=$(echo "$RESPONSE" | jq -r '.data.ticket')
    CSRF_TOKEN=$(echo "$RESPONSE" | jq -r '.data.CSRFPreventionToken')

    if [ "$TICKET" == "null" ] || [ -z "$TICKET" ]; then
        echo -e "${RED}[!] Authentication Failed.${NC}"
        echo "Response: $RESPONSE"
        exit 1
    fi
    echo -e "${GREEN}[+] Connection Established.${NC}"
    sleep 1
}

pve_api() {
    local METHOD=$1
    local ENDPOINT=$2
    local DATA=$3

    if [ -z "$DATA" ]; then
        curl -s -k -X "$METHOD" \
            -H "CSRFPreventionToken: $CSRF_TOKEN" \
            -H "Cookie: PVEAuthCookie=$TICKET" \
            "https://$PVE_HOST:8006/api2/json/$ENDPOINT"
    else
        curl -s -k -X "$METHOD" \
            -H "CSRFPreventionToken: $CSRF_TOKEN" \
            -H "Cookie: PVEAuthCookie=$TICKET" \
            -d "$DATA" \
            "https://$PVE_HOST:8006/api2/json/$ENDPOINT"
    fi
}

live_dashboard() {
    while true; do
        clear
        echo -e "${WHITE}=== PROXMOX LIVE CLUSTER STATS ===${NC} (Press 'q' and Enter to go back)"
        echo -e "Last Updated: $(date)"
        echo "------------------------------------------------------------"
        
        DATA=$(pve_api GET "cluster/resources")
        
        echo -e "${CYAN}NODES:${NC}"
        echo "$DATA" | jq -r '.data[] | select(.type=="node") | "  \(.node): CPU: \((.cpu*100)|round)% | Mem: \((.mem/1024/1024/1024)|round)GB / \((.maxmem/1024/1024/1024)|round)GB | Status: \(.status)"'
        
        echo -e "\n${CYAN}TOP VIRTUAL MACHINES (QEMU):${NC}"
        echo "$DATA" | jq -r '.data[] | select(.type=="qemu" and .status=="running") | "  [\(.vmid)] \(.name) | CPU: \((.cpu*100)|round)% | Mem: \((.mem/1024/1024)|round)MB"' | head -n 5

        echo -e "\n${GREEN}TOP CONTAINERS (LXC):${NC}"
        echo "$DATA" | jq -r '.data[] | select(.type=="lxc" and .status=="running") | "  [\(.vmid)] \(.name) | CPU: \((.cpu*100)|round)% | Mem: \((.mem/1024/1024)|round)MB"' | head -n 5
        
        # Non-blocking read attempt for 'q'
        read -t 3 -n 1 OPT
        if [[ "$OPT" == "q" || "$OPT" == "b" ]]; then return; fi
    done
}

view_cluster_log() {
    echo -e "${PURPLE}--- Recent Cluster Tasks ---${NC}"
    TASKS=$(pve_api GET "cluster/tasks")
    echo "$TASKS" | jq -r '.data[] | "[\(.starttime | todate)] UPID: \(.upid) | User: \(.user) | Type: \(.type) | Status: \(.status)"' | head -n 20
    
    echo -e "\nDo you want to see the detailed log of a specific task?"
    read -p "Enter UPID (or 'b' to back): " UPID
    if [[ "$UPID" == "b" || -z "$UPID" ]]; then return; fi
    
    NODE_FROM_UPID=$(echo "$UPID" | cut -d':' -f2)
    echo -e "${YELLOW}Fetching log from node $NODE_FROM_UPID...${NC}"
    pve_api GET "nodes/$NODE_FROM_UPID/tasks/$UPID/log" | jq -r '.data[] | "\(.n). \(.t)"'
}

view_ha_status() {
    echo -e "${PURPLE}--- HA Status ---${NC}"
    pve_api GET "cluster/ha/status/current" | jq -r '.data[] | "Status: \(.status)"' 
}

check_cluster_quorum() {
    echo -e "${PURPLE}--- Corosync / Quorum Status ---${NC}"
    pve_api GET "cluster/status" | jq -r '.data[] | "[\(.type)] \(.name) | ID: \(.id) | Quorum: \(.quorate // .online)"'
}

check_pve_version() {
    echo -e "${PURPLE}--- Version Info ---${NC}"
    pve_api GET "version" | jq .data
}

manage_users() {
    echo -e "${YELLOW}--- User Management ---${NC}"
    echo "1. List Users"
    echo "2. Create User"
    echo "3. Change User Password"
    echo "b. Back"
    read -p "Select: " UOPT

    case $UOPT in
        1) pve_api GET "access/users" | jq -r '.data[] | "User: \(.userid) | Enabled: \(.enable)"' ;;
        2) 
           read -p "Username (e.g. john): " NEWUSER
           read -s -p "Password: " NEWPASS; echo ""
           pve_api POST "access/users" "userid=$NEWUSER@pve&password=$NEWPASS" | jq .
           pve_api PUT "access/acl" "path=/&roles=PVEAuditor&users=$NEWUSER@pve"
           echo "User created with PVEAuditor role." 
           ;;
        3) 
           read -p "Username (e.g. root@pam): " TARGUSER
           read -s -p "New Password: " NEWPASS; echo ""
           pve_api PUT "access/password" "userid=$TARGUSER&password=$NEWPASS" | jq .
           ;;
        b|B|q|Q) return ;;
    esac
}

manage_backup_jobs() {
    echo -e "${YELLOW}--- Cluster Backup Jobs ---${NC}"
    echo "1. List Jobs"
    echo "2. Run Job Now"
    echo "b. Back"
    read -p "Select: " BOPT
    
    case $BOPT in
        1) pve_api GET "cluster/backup" | jq -r '.data[] | "ID: \(.id) | Schedule: \(.schedule) | Storage: \(.storage) | Node: \(.node // "All")"' ;;
        2) 
           read -p "Job ID: " JID
           pve_api POST "cluster/backup/$JID/run" | jq . 
           ;;
        b|B) return ;;
    esac
}

manage_replication() {
    echo -e "${YELLOW}--- ZFS Replication ---${NC}"
    pve_api GET "cluster/replication" | jq -r '.data[] | "ID: \(.id) | Job: \(.jobid) | Target: \(.target) | Last Sync: \(.last_sync | todate)"'
}

manage_sdn() {
    echo -e "${YELLOW}--- SDN (Software Defined Network) ---${NC}"
    echo "Zones:"
    pve_api GET "cluster/sdn/zones" | jq -r '.data[] | "  \(.zone) (Type: \(.type))"'
    echo "VNets:"
    pve_api GET "cluster/sdn/vnets" | jq -r '.data[] | "  \(.vnet) (Zone: \(.zone))"'
}

manage_pools() {
    echo -e "${YELLOW}--- Resource Pools ---${NC}"
    echo "1. List Pools"
    echo "2. Create Pool"
    echo "3. Delete Pool"
    echo "b. Back"
    read -p "Select: " POPT
    
    case $POPT in
        1) pve_api GET "pools" | jq -r '.data[] | "Pool: \(.poolid) | Comment: \(.comment)"' ;;
        2) read -p "Pool ID: " PID; pve_api POST "pools" "poolid=$PID" | jq . ;;
        3) read -p "Pool ID: " PID; pve_api DELETE "pools/$PID" | jq . ;;
        b|B) return ;;
    esac
}

manage_storage_cfg() {
    echo -e "${YELLOW}--- Global Storage Configuration ---${NC}"
    echo "1. List Storage Configs"
    echo "2. Add Directory Storage"
    echo "3. Add NFS Storage"
    echo "4. Remove Storage"
    echo "b. Back"
    read -p "Select: " SOPT
    
    case $SOPT in
        1) pve_api GET "storage" | jq -r '.data[] | "ID: \(.storage) | Type: \(.type) | Content: \(.content)"' ;;
        2) 
           read -p "ID (e.g. backup-dir): " ID
           read -p "Path (e.g. /mnt/backups): " PATH
           read -p "Content (iso,vztmpl,backup,images): " CONT
           pve_api POST "storage" "storage=$ID&type=dir&path=$PATH&content=$CONT" | jq . 
           ;;
        3)
           read -p "ID (e.g. nas-01): " ID
           read -p "Server IP: " SRV
           read -p "Export Path: " EXP
           read -p "Content (iso,vztmpl,backup,images): " CONT
           pve_api POST "storage" "storage=$ID&type=nfs&server=$SRV&export=$EXP&content=$CONT" | jq .
           ;;
        4) read -p "Storage ID to delete: " ID; pve_api DELETE "storage/$ID" | jq . ;;
        b|B) return ;;
    esac
}

manage_ceph() {
    echo -e "${YELLOW}--- Ceph Cluster Status ---${NC}"
    STATUS=$(pve_api GET "cluster/ceph/status")
    if echo "$STATUS" | grep -q "not installed"; then
        echo "Ceph is not installed or configured on this cluster."
        return
    fi
    echo "$STATUS" | jq -r '.data.health.status' 
    echo "--- OSD Tree ---"
    pve_api GET "cluster/ceph/osd/tree" | jq -r '.data[] | "Name: \(.name) | Type: \(.type) | Status: \(.status)"'
}

manage_cluster_firewall() {
    echo -e "${YELLOW}--- Cluster Firewall ---${NC}"
    echo "1. List Security Groups"
    echo "2. List IPSet/Aliases"
    echo "3. List Policies"
    echo "b. Back"
    read -p "Select: " FOPT
    
    case $FOPT in
        1) pve_api GET "cluster/firewall/groups" | jq -r '.data[] | "Group: \(.group) | Comment: \(.comment)"' ;;
        2) pve_api GET "cluster/firewall/aliases" | jq -r '.data[] | "Name: \(.name) | IP: \(.cidr)"' ;;
        3) pve_api GET "cluster/firewall/options" | jq '.data' ;;
        b|B) return ;;
    esac
}

get_join_info() {
    echo -e "${YELLOW}--- Cluster Join Information ---${NC}"
    echo -e "${RED}Warning: This exposes the join key.${NC}"
    pve_api GET "cluster/config/join" | jq -r '.data | "IP: \(.ip_address_list[0])\nFingerprint: \(.nodelist[].pve_fp)\n\nTOTEM KEY: \(.totem.secauth)"'
}

manage_metric_servers() {
    echo -e "${YELLOW}--- Metric Servers ---${NC}"
    echo "1. List Metric Servers"
    echo "2. Add InfluxDB"
    echo "b. Back"
    read -p "Select: " MOPT
    
    case $MOPT in
        1) pve_api GET "cluster/metrics/server" | jq -r '.data[] | "ID: \(.id) | Server: \(.server) | Port: \(.port) | Type: \(.type)"' ;;
        2) 
           read -p "ID (e.g. influx): " ID
           read -p "Server IP: " SRV
           read -p "Port: " PORT
           pve_api POST "cluster/metrics/server/$ID" "type=influxdb&server=$SRV&port=$PORT" | jq .
           ;;
        b|B) return ;;
    esac
}

manage_notifications() {
    echo -e "${YELLOW}--- Notifications (PVE 8.1+) ---${NC}"
    echo "Targets:"
    pve_api GET "cluster/notifications/targets" | jq -r '.data[] | "  \(.name) (\(.type))"'
    echo "Matchers:"
    pve_api GET "cluster/notifications/matchers" | jq -r '.data[] | "  \(.name) -> Target: \(.target)"'
}

manage_auth_realms() {
    echo -e "${YELLOW}--- Authentication Realms ---${NC}"
    echo "1. List Realms"
    echo "2. Sync Realm (LDAP/AD)"
    echo "b. Back"
    read -p "Select: " ROPT
    
    case $ROPT in
        1) pve_api GET "access/domains" | jq -r '.data[] | "Realm: \(.realm) | Type: \(.type) | Default: \(.default // 0)"' ;;
        2) read -p "Realm Name: " RNAME; pve_api POST "access/domains/$RNAME/sync" | jq . ;;
        b|B) return ;;
    esac
}

manage_groups_roles() {
    echo -e "${YELLOW}--- Groups & Roles ---${NC}"
    echo "1. List Groups"
    echo "2. List Roles"
    echo "3. Create Group"
    echo "b. Back"
    read -p "Select: " GROPT
    
    case $GROPT in
        1) pve_api GET "access/groups" | jq -r '.data[] | "Group: \(.groupid)"' ;;
        2) pve_api GET "access/roles" | jq -r '.data[] | "Role: \(.roleid) | Privs: \(.privs)"' ;;
        3) read -p "New Group ID: " GID; pve_api POST "access/groups" "groupid=$GID" | jq . ;;
        b|B) return ;;
    esac
}

list_nodes() { pve_api GET "nodes" | jq -r '.data[] | .node'; }

check_updates() {
    local NODE=$1
    echo -e "${BLUE}checking updates for $NODE...${NC}"
    pve_api POST "nodes/$NODE/apt/update" | jq .
    echo "Listing upgrades:"
    pve_api GET "nodes/$NODE/apt/update" | jq -r '.data[] | "Pkg: \(.Package) | Old: \(.OldVersion) -> New: \(.Version)"'
}

view_node_network() {
    local NODE=$1
    echo -e "${PURPLE}--- Network Interfaces on $NODE ---${NC}"
    pve_api GET "nodes/$NODE/network" | jq -r '.data[] | "If: \(.iface) | Type: \(.type) | Active: \(.active) | CIDR: \(.cidr // "N/A")"'
}

manage_disks() {
    local NODE=$1
    echo -e "${PURPLE}--- Disks on $NODE ---${NC}"
    pve_api GET "nodes/$NODE/disks/list" | jq -r '.data[] | "Dev: \(.devpath) | Size: \((.size/1024/1024/1024)|round)GB | Type: \(.type) | Model: \(.model)"'
    echo -e "${PURPLE}--- ZFS Pools ---${NC}"
    pve_api GET "nodes/$NODE/disks/zfs" | jq -r '.data[] | "Pool: \(.name) | Health: \(.health) | Free: \((.free/1024/1024/1024)|round)GB"'
}

manage_certs() {
    local NODE=$1
    echo -e "${PURPLE}--- Certificates on $NODE ---${NC}"
    pve_api GET "nodes/$NODE/certificates/info" | jq -r '.data[] | "Subject: \(.subject) | Issuer: \(.issuer) | Expires: \(.notAfter | todate)"'
}

manage_node_system() {
    local NODE=$1
    echo -e "${PURPLE}--- System Config for $NODE ---${NC}"
    echo "[Time]"
    pve_api GET "nodes/$NODE/time" | jq -r '.data | "Time: \(.localtime) | Zone: \(.timezone)"'
    echo "[DNS]"
    pve_api GET "nodes/$NODE/dns" | jq -r '.data | "Search: \(.search) | DNS1: \(.dns1) | DNS2: \(.dns2)"'
    echo "[Subscription]"
    pve_api GET "nodes/$NODE/subscription" | jq -r '.data | "Status: \(.status) | Level: \(.level)"'
}

manage_services() {
    local NODE=$1
    echo -e "${PURPLE}--- Service Manager ($NODE) ---${NC}"
    echo "1. List Running Services"
    echo "2. Restart Service"
    echo "3. Stop Service"
    echo "4. Start Service"
    echo "b. Back"
    read -p "Select: " SOPT
    
    case $SOPT in
        1) pve_api GET "nodes/$NODE/services" | jq -r '.data[] | select(.state=="running") | .service' ;;
        2) read -p "Service Name (e.g. pveproxy): " SVCNAME; pve_api POST "nodes/$NODE/services/$SVCNAME/reload" | jq . ;;
        3) read -p "Service Name: " SVCNAME; pve_api POST "nodes/$NODE/services/$SVCNAME/stop" | jq . ;;
        4) read -p "Service Name: " SVCNAME; pve_api POST "nodes/$NODE/services/$SVCNAME/start" | jq . ;;
        b|B) return ;;
    esac
}

view_node_syslog() {
    local NODE=$1
    echo -e "${PURPLE}--- Last 20 System Logs ($NODE) ---${NC}"
    pve_api GET "nodes/$NODE/syslog" | jq -r '.data[] | "\(.t) \(.n)"' | tail -n 20
}

download_to_storage() {
    local NODE=$1
    echo -e "${CYAN}--- Download ISO/CT Template from URL ---${NC}"
    pve_api GET "nodes/$NODE/storage" | jq -r '.data[] | "Storage: \(.storage) (Content: \(.content))"'
    
    read -p "Target Storage ID (e.g. local) or 'b' to back: " STORE
    if [[ "$STORE" == "b" ]]; then return; fi

    read -p "Content Type (iso OR vztmpl): " TYPE
    read -p "URL to Download: " URL
    read -p "Output Filename (e.g. alpine.iso): " FNAME
    
    echo -e "${YELLOW}Starting download task...${NC}"
    pve_api POST "nodes/$NODE/storage/$STORE/download-url" "content=$TYPE&filename=$FNAME&url=$URL" | jq .
}

manage_repositories() {
    local NODE=$1
    echo -e "${CYAN}--- APT Repository Manager ($NODE) ---${NC}"
    echo "1. List Repositories"
    echo "b. Back"
    read -p "Select: " ROPT
    if [ "$ROPT" == "1" ]; then
        pve_api GET "nodes/$NODE/apt/repositories" | jq -r '.data.files[] | .repositories[] | "[\(.Enabled // false)] \(.URIs)"'
    fi
}

manage_pci_usb() {
    local NODE=$1
    echo -e "${CYAN}--- Hardware Passthrough Info ($NODE) ---${NC}"
    echo "1. List PCI Devices"
    echo "2. List USB Devices"
    echo "b. Back"
    read -p "Select: " HOPT
    
    case $HOPT in
        1) pve_api GET "nodes/$NODE/hardware/pci" | jq -r '.data[] | "ID: \(.id) | Vendor: \(.vendor_name) | Device: \(.device_name)"' ;;
        2) pve_api GET "nodes/$NODE/hardware/usb" | jq -r '.data[] | "Bus: \(.busnum) | Port: \(.portnum) | Vendor: \(.vendorid) | Prod: \(.product)"' ;;
        b|B) return ;;
    esac
}

manage_backup_files() {
    local NODE=$1
    echo -e "${CYAN}--- Backup File Management ($NODE) ---${NC}"
    pve_api GET "nodes/$NODE/storage" | jq -r '.data[] | select(.content | contains("backup")) | .storage'
    read -p "Select Storage ID: " STORE
    
    echo "1. List Backups"
    echo "2. Delete Backup Volume"
    echo "3. Restore Backup to New VM"
    echo "b. Back"
    read -p "Select: " BOPT
    
    case $BOPT in
        1) 
           pve_api GET "nodes/$NODE/storage/$STORE/content" | jq -r '.data[] | select(.content=="backup") | "VolID: \(.volid) | Size: \((.size/1024/1024)|round)MB"' 
           ;;
        2) 
           read -p "Volume ID to delete (e.g. local:backup/vzdump...): " VOL
           pve_api DELETE "nodes/$NODE/storage/$STORE/content/$VOL" | jq . 
           ;;
        3)
           read -p "Volume ID to restore: " VOL
           read -p "New VMID: " NEWID
           echo "1. VM (QEMU), 2. CT (LXC)"
           read -p "Type: " T
           if [ "$T" == "1" ]; then
                pve_api POST "nodes/$NODE/qemu" "vmid=$NEWID&archive=$VOL&storage=$STORE" | jq .
           else
                pve_api POST "nodes/$NODE/lxc" "vmid=$NEWID&ostemplate=$VOL&storage=$STORE&restore=1" | jq .
           fi
           ;;
        b|B) return ;;
    esac
}

bulk_power() {
    local NODE=$1
    echo -e "${RED}--- BULK POWER ACTIONS ($NODE) ---${NC}"
    echo "1. Start ALL VMs & CTs"
    echo "2. Stop ALL VMs & CTs"
    echo "b. Back"
    read -p "Select: " BOPT
    if [ "$BOPT" == "1" ]; then
        pve_api POST "nodes/$NODE/startall" | jq .
    elif [ "$BOPT" == "2" ]; then
        pve_api POST "nodes/$NODE/stopall" | jq .
    fi
}

create_lxc() {
    local NODE=$1
    echo -e "${CYAN}--- LXC Container Creator ---${NC}"
    echo "Available Templates:"
    pve_api GET "nodes/$NODE/storage/local/content" | jq -r '.data[] | select(.content=="vztmpl") | .volid'
    
    read -p "Template VolID (e.g., local:vztmpl/ubuntu...): " TEMPLATE
    read -p "New CT ID: " CTID
    read -p "Hostname: " HOSTNAME
    read -p "Password: " PASS
    read -p "Storage (e.g., local-lvm): " STORAGE
    
    echo -e "${YELLOW}Creating Container $CTID...${NC}"
    pve_api POST "nodes/$NODE/lxc" "vmid=$CTID&ostemplate=$TEMPLATE&hostname=$HOSTNAME&password=$PASS&storage=$STORAGE&memory=512&cores=1&net0=name=eth0,bridge=vmbr0,ip=dhcp" | jq .
}

migrate_vm_or_ct() {
    local NODE=$1
    echo "1. Migrate VM (QEMU)"
    echo "2. Migrate Container (LXC)"
    echo "b. Back"
    read -p "Select Type: " T
    
    if [[ "$T" == "b" ]]; then return; fi
    
    read -p "ID to Migrate: " ID
    read -p "Target Node Name: " TARGET
    
    if [ "$T" == "1" ]; then
        echo -e "${YELLOW}Migrating VM $ID to $TARGET...${NC}"
        pve_api POST "nodes/$NODE/qemu/$ID/migrate" "target=$TARGET&online=1&with-local-disks=1" | jq .
    elif [ "$T" == "2" ]; then
        echo -e "${YELLOW}Migrating CT $ID to $TARGET...${NC}"
        pve_api POST "nodes/$NODE/lxc/$ID/migrate" "target=$TARGET&online=1" | jq .
    fi
}

power_control() {
    local NODE=$1
    echo "1. VM (QEMU)"
    echo "2. Container (LXC)"
    echo "b. Back"
    read -p "Select Type: " T
    
    if [[ "$T" == "b" ]]; then return; fi

    read -p "ID: " ID
    read -p "Action (start/stop/shutdown/reset/reboot): " ACT
    
    if [ "$T" == "1" ]; then
        pve_api POST "nodes/$NODE/qemu/$ID/status/$ACT" | jq .
    elif [ "$T" == "2" ]; then
        pve_api POST "nodes/$NODE/lxc/$ID/status/$ACT" | jq .
    fi
}

manage_firewall() {
    local NODE=$1
    read -p "VMID: " VMID
    echo "1. Show Firewall Options"
    echo "2. Enable Firewall"
    echo "3. Disable Firewall"
    echo "b. Back"
    read -p "Select: " FOPT

    case $FOPT in
        1) pve_api GET "nodes/$NODE/qemu/$VMID/firewall/options" | jq '.data' ;;
        2) pve_api PUT "nodes/$NODE/qemu/$VMID/firewall/options" "enable=1" | jq .; echo "Firewall Enabled." ;;
        3) pve_api PUT "nodes/$NODE/qemu/$VMID/firewall/options" "enable=0" | jq .; echo "Firewall Disabled." ;;
        b|B) return ;;
    esac
}

generate_vnc() {
    local NODE=$1
    read -p "ID: " ID
    echo "1. VM"
    echo "2. LXC"
    read -p "Type: " T
    echo -e "${YELLOW}Generating VNC Ticket...${NC}"
    if [ "$T" == "1" ]; then
        pve_api POST "nodes/$NODE/qemu/$ID/vncproxy" | jq .
    else
        pve_api POST "nodes/$NODE/lxc/$ID/vncproxy" | jq .
    fi
    echo -e "${CYAN}Note: CLI cannot render VNC. Use the ticket above with a VNC client or Web UI.${NC}"
}

manage_cdrom() {
    local NODE=$1
    read -p "VMID: " VMID
    echo "--- Available ISOs ---"
    pve_api GET "nodes/$NODE/storage/local/content" | jq -r '.data[] | select(.content=="iso") | .volid'
    
    read -p "Enter Full ISO VolID (e.g. local:iso/ubuntu.iso) or 'none' to eject: " ISO
    if [ "$ISO" == "none" ]; then ISO="none,media=cdrom"; else ISO="$ISO,media=cdrom"; fi
    
    echo -e "${YELLOW}Setting IDE2 to $ISO...${NC}"
    pve_api POST "nodes/$NODE/qemu/$VMID/config" "ide2=$ISO" | jq .
}

resize_vm() {
    local NODE=$1
    local VMID=$2
    echo -e "${YELLOW}VM Hardware Manager for $VMID${NC}"
    echo "1. Change CPU Cores"
    echo "2. Change Memory (MB)"
    echo "b. Back"
    read -p "Select: " HW_OPT
    if [ "$HW_OPT" == "1" ]; then
        read -p "New Core Count: " CORES; pve_api POST "nodes/$NODE/qemu/$VMID/config" "cores=$CORES" | jq .
    elif [ "$HW_OPT" == "2" ]; then
        read -p "New Memory (MB): " MEM; pve_api POST "nodes/$NODE/qemu/$VMID/config" "memory=$MEM" | jq .
    fi
}

clone_vm() {
    local NODE=$1
    read -p "Source VMID: " SRCID; read -p "New VMID: " NEWID; read -p "New Name: " NAME
    pve_api POST "nodes/$NODE/qemu/$SRCID/clone" "newid=$NEWID&name=$NAME&full=1" | jq .
}

convert_to_template() {
    local NODE=$1
    read -p "VMID to convert to template: " VMID
    echo -e "${RED}Warning: This is irreversible.${NC}"
    read -p "Are you sure? (y/n): " SURE
    if [ "$SURE" == "y" ]; then
        pve_api POST "nodes/$NODE/qemu/$VMID/template" | jq .
    fi
}

add_usb_vm() {
    local NODE=$1
    read -p "VMID: " VMID
    echo "Available USB Devices:"
    pve_api GET "nodes/$NODE/hardware/usb" | jq -r '.data[] | "Bus: \(.busnum) | Port: \(.portnum) | ID: \(.vendorid):\(.productid) (\(.product))"'
    
    read -p "Enter Vendor:Product ID (e.g. 0951:1666): " USBID
    echo -e "${YELLOW}Adding USB device $USBID to VM $VMID...${NC}"
    pve_api POST "nodes/$NODE/qemu/$VMID/config" "usb0=host=$USBID" | jq .
}

manage_vm_cloudinit() {
    local NODE=$1
    local VMID=$2
    echo -e "${CYAN}--- Cloud-Init Config ($VMID) ---${NC}"
    pve_api GET "nodes/$NODE/qemu/$VMID/config" | jq -r '.data | "User: \(.ciuser) | IP: \(.ipconfig0 // "N/A") | SSHKey: \(.sshkeys)"'
    
    echo "1. Set User/Password"
    echo "2. Set IP (Static)"
    echo "3. Set IP (DHCP)"
    echo "b. Back"
    read -p "Select: " COPT
    
    case $COPT in
        1) 
           read -p "CI User: " U; read -s -p "CI Password: " P; echo ""
           pve_api POST "nodes/$NODE/qemu/$VMID/config" "ciuser=$U&cipassword=$P" | jq . 
           ;;
        2) 
           read -p "CIDR (e.g. 192.168.1.50/24): " IP; read -p "Gateway: " GW
           pve_api POST "nodes/$NODE/qemu/$VMID/config" "ipconfig0=ip=$IP,gw=$GW" | jq . 
           ;;
        3) pve_api POST "nodes/$NODE/qemu/$VMID/config" "ipconfig0=ip=dhcp" | jq . ;;
        b|B) return ;;
    esac
}

get_vm_agent() {
    local NODE=$1
    local VMID=$2
    echo -e "${CYAN}--- QEMU Agent Status ($VMID) ---${NC}"
    pve_api GET "nodes/$NODE/qemu/$VMID/agent/info" | jq .
    echo -e "${CYAN}--- Network Interfaces (via Agent) ---${NC}"
    pve_api GET "nodes/$NODE/qemu/$VMID/agent/network-get-interfaces" | jq -r '.data.result[] | "\(.name): \(.["ip-addresses"][0]["ip-address"])"'
}

view_raw_config() {
    local NODE=$1
    echo "1. VM"
    echo "2. CT"
    read -p "Type: " T
    read -p "ID: " ID
    if [ "$T" == "1" ]; then
        pve_api GET "nodes/$NODE/qemu/$ID/config" | jq .data
    else
        pve_api GET "nodes/$NODE/lxc/$ID/config" | jq .data
    fi
}

manage_lxc_resources() {
    local NODE=$1
    local VMID=$2
    echo -e "${GREEN}LXC Resource Manager for $VMID${NC}"
    echo "1. Change CPU Cores"
    echo "2. Change Memory (MB)"
    echo "3. Change Swap (MB)"
    echo "4. Resize Root Disk (GB)"
    echo "b. Back"
    read -p "Select: " LOPT
    
    case $LOPT in
        1) read -p "Cores: " C; pve_api PUT "nodes/$NODE/lxc/$VMID/config" "cores=$C" | jq . ;;
        2) read -p "Memory (MB): " M; pve_api PUT "nodes/$NODE/lxc/$VMID/config" "memory=$M" | jq . ;;
        3) read -p "Swap (MB): " S; pve_api PUT "nodes/$NODE/lxc/$VMID/config" "swap=$S" | jq . ;;
        4) read -p "Size to ADD (e.g. +2G): " S; pve_api PUT "nodes/$NODE/lxc/$VMID/resize" "disk=rootfs&size=$S" | jq . ;;
        b|B) return ;;
    esac
}

manage_lxc_network() {
    local NODE=$1
    local VMID=$2
    echo -e "${GREEN}LXC Network Manager ($VMID)${NC}"
    echo "1. Set Static IP (net0)"
    echo "2. Set DHCP (net0)"
    echo "3. Change Gateway"
    echo "b. Back"
    read -p "Select: " NOPT
    
    case $NOPT in
        1) 
           read -p "IPv4/CIDR: " IP; read -p "Gateway: " GW
           pve_api PUT "nodes/$NODE/lxc/$VMID/config" "net0=name=eth0,bridge=vmbr0,ip=$IP,gw=$GW" | jq . 
           ;;
        2) pve_api PUT "nodes/$NODE/lxc/$VMID/config" "net0=name=eth0,bridge=vmbr0,ip=dhcp" | jq . ;;
        3) 
           read -p "New Gateway IP: " GW
           echo "Note: This overrides net0 to static/bridge=vmbr0."
           read -p "Confirm IP/CIDR to keep: " IP
           pve_api PUT "nodes/$NODE/lxc/$VMID/config" "net0=name=eth0,bridge=vmbr0,ip=$IP,gw=$GW" | jq . 
           ;;
        b|B) return ;;
    esac
}

manage_lxc_dns() {
    local NODE=$1
    local VMID=$2
    echo -e "${GREEN}LXC DNS & Hostname ($VMID)${NC}"
    echo "1. Set Hostname"
    echo "2. Set DNS Servers"
    echo "b. Back"
    read -p "Select: " DOPT
    
    case $DOPT in
        1) read -p "New Hostname: " H; pve_api PUT "nodes/$NODE/lxc/$VMID/config" "hostname=$H" | jq . ;;
        2) read -p "DNS Server IP (e.g. 8.8.8.8): " D; pve_api PUT "nodes/$NODE/lxc/$VMID/config" "nameserver=$D" | jq . ;;
        b|B) return ;;
    esac
}

clone_lxc() {
    local NODE=$1
    read -p "Source CT ID: " SRCID
    read -p "New CT ID: " NEWID
    read -p "New Hostname: " NAME
    echo -e "${GREEN}Cloning Container $SRCID -> $NEWID...${NC}"
    pve_api POST "nodes/$NODE/lxc/$SRCID/clone" "newid=$NEWID&hostname=$NAME" | jq .
}

manage_lxc_snapshots() {
    local NODE=$1
    read -p "Container ID: " ID
    echo "1. List Snapshots"
    echo "2. Create Snapshot"
    read -p "Choice: " SNAP_OPT
    if [ "$SNAP_OPT" == "1" ]; then pve_api GET "nodes/$NODE/lxc/$ID/snapshot" | jq -r '.data[] | .name'; fi
    if [ "$SNAP_OPT" == "2" ]; then read -p "Name: " N; pve_api POST "nodes/$NODE/lxc/$ID/snapshot" "snapname=$N" | jq .; fi
}

convert_lxc_template() {
    local NODE=$1
    read -p "CT ID to convert to template: " ID
    echo -e "${RED}Warning: This is irreversible.${NC}"
    read -p "Are you sure? (y/n): " SURE
    if [ "$SURE" == "y" ]; then
        pve_api POST "nodes/$NODE/lxc/$ID/template" | jq .
    fi
}

delete_lxc() {
    local NODE=$1
    echo -e "${RED}--- DELETE LXC CONTAINER ---${NC}"
    read -p "Enter Container ID to PERMANENTLY DELETE: " CTID
    
    # Safety Check
    echo -e "${RED}WARNING: This action cannot be undone.${NC}"
    read -p "Are you sure? Type the ID '$CTID' to confirm: " CONFIRM
    
    if [ "$CTID" == "$CONFIRM" ]; then
        echo -e "${YELLOW}Deleting Container $CTID...${NC}"
        pve_api DELETE "nodes/$NODE/lxc/$CTID" | jq .
    else
        echo "Confirmation mismatch. Aborting."
    fi
}

create_advanced_api() {
    echo -e "${CYAN}=== Advanced Token Generator ===${NC}"
    echo "1. Delegate specific VMs (Admin access)"
    echo "2. Delegate specific Storage (Upload access)"
    echo "3. Delegate Read-Only Cluster Access"
    echo "b. Back"
    read -p "Select Mode: " MODE

    if [[ "$MODE" == "b" ]]; then return; fi

    read -p "Enter new API User name (default: api-bot): " API_USER
    API_USER=${API_USER:-api-bot}
    FULL_USER="$API_USER@pve"
    TOKEN_NAME="gen$(date +%s)"

    pve_api POST "access/users" "userid=$FULL_USER&comment=AutoGen" > /dev/null

    if [ "$MODE" == "1" ]; then
        read -p "Enter VMIDs (comma separated): " LIST
        IFS=',' read -ra ADDR <<< "$LIST"
        for id in "${ADDR[@]}"; do
            id=$(echo $id | xargs)
            pve_api PUT "access/acl" "path=/vms/$id&roles=PVEVMAdmin&users=$FULL_USER" > /dev/null
        done
    elif [ "$MODE" == "2" ]; then
        read -p "Enter Storage ID (e.g. local): " STORE
        pve_api PUT "access/acl" "path=/storage/$STORE&roles=PVEDatastoreAdmin&users=$FULL_USER" > /dev/null
    elif [ "$MODE" == "3" ]; then
        pve_api PUT "access/acl" "path=/&roles=PVEAuditor&users=$FULL_USER" > /dev/null
    fi

    TOKEN_RESP=$(pve_api POST "access/users/$FULL_USER/token/$TOKEN_NAME" "privsep=0")
    SECRET=$(echo "$TOKEN_RESP" | jq -r '.data.value')
    
    echo -e "\n${GREEN}=== API KEY CREATED ===${NC}"
    echo -e "User: $FULL_USER | Token: $TOKEN_NAME"
    echo -e "Secret: ${CYAN}$SECRET${NC}"
}

menu_vm() {
    local NODE=$1
    while true; do
        clear
        echo -e "\n${CYAN}=== VM & Container Management ($NODE) ===${NC}"
        echo "1. List All (VMs & CTs)"
        echo "2. Power Control (Start/Stop)"
        echo "3. Get VNC Ticket"
        echo "4. Migrate (Move Node)"
        echo "5. View Raw Config (Expert)"
        echo -e "${YELLOW}[ VM / QEMU Operations ]${NC}"
        echo "6. VM Hardware (CPU/RAM)"
        echo "7. VM Cloud-Init"
        echo "8. VM CD-ROM / ISO"
        echo "9. VM Clone"
        echo "10. VM Snapshot"
        echo "11. VM -> Template"
        echo "12. Add USB Device"
        echo -e "${GREEN}[ CONTAINER / LXC Operations ]${NC}"
        echo "13. Create New LXC"
        echo "14. LXC Resources (CPU/RAM/Disk)"
        echo "15. LXC Network (IP/Gateway)"
        echo "16. LXC DNS & Hostname"
        echo "17. LXC Clone"
        echo "18. LXC Snapshot"
        echo "19. LXC -> Template"
        echo "20. Delete LXC"
        echo "0. Back to Node Menu"
        read -p "Select: " OPT

        case $OPT in
            1) 
               pve_api GET "nodes/$NODE/qemu" | jq -r '.data[] | "VM \(.vmid): \(.name) (\(.status))"'
               pve_api GET "nodes/$NODE/lxc" | jq -r '.data[] | "CT \(.vmid): \(.name) (\(.status))"'
               pause_action
               ;;
            2) power_control "$NODE"; pause_action ;;
            3) generate_vnc "$NODE"; pause_action ;;
            4) migrate_vm_or_ct "$NODE"; pause_action ;;
            5) view_raw_config "$NODE"; pause_action ;;
            6) read -p "VMID: " ID; resize_vm "$NODE" "$ID"; pause_action ;;
            7) read -p "VMID: " ID; manage_vm_cloudinit "$NODE" "$ID"; pause_action ;;
            8) manage_cdrom "$NODE"; pause_action ;;
            9) clone_vm "$NODE"; pause_action ;;
            10) read -p "VMID: " ID; pve_api GET "nodes/$NODE/qemu/$ID/snapshot" | jq -r '.data[] | .name'; pause_action ;;
            11) convert_to_template "$NODE"; pause_action ;;
            12) add_usb_vm "$NODE"; pause_action ;;
            13) create_lxc "$NODE"; pause_action ;;
            14) read -p "CTID: " ID; manage_lxc_resources "$NODE" "$ID"; pause_action ;;
            15) read -p "CTID: " ID; manage_lxc_network "$NODE" "$ID"; pause_action ;;
            16) read -p "CTID: " ID; manage_lxc_dns "$NODE" "$ID"; pause_action ;;
            17) clone_lxc "$NODE"; pause_action ;;
            18) manage_lxc_snapshots "$NODE"; pause_action ;;
            19) convert_lxc_template "$NODE"; pause_action ;;
            20) delete_lxc "$NODE"; pause_action ;;
            b|B|q|Q|0) return ;;
            *) echo "Invalid option"; pause_action ;;
        esac
    done
}

menu_node() {
    local NODE=$1
    while true; do
        clear
        echo -e "\n${PURPLE}=== Node Operations ($NODE) ===${NC}"
        echo "1. System Status"
        echo "2. Network Interfaces"
        echo "3. Disks (ZFS/LVM)"
        echo "4. APT Repositories"
        echo "5. Check Updates (APT)"
        echo "6. Hardware (PCI/USB)"
        echo "7. Certificates"
        echo "8. Manage VMs/CTs"
        echo "9. System (DNS/Time/Sub)"
        echo "10. Service Manager"
        echo "11. View System Log (Syslog)"
        echo "12. Download ISO/Template from URL"
        echo "13. Backup File Manager (Restore/Delete)"
        echo "14. Bulk Actions (Start/Stop All)"
        echo "0. Back to Main Menu"
        read -p "Select: " OPT

        case $OPT in
            1) pve_api GET "nodes/$NODE/status" | jq .data; pause_action ;;
            2) view_node_network "$NODE"; pause_action ;;
            3) manage_disks "$NODE"; pause_action ;;
            4) manage_repositories "$NODE"; pause_action ;;
            5) check_updates "$NODE"; pause_action ;;
            6) manage_pci_usb "$NODE"; pause_action ;;
            7) manage_certs "$NODE"; pause_action ;;
            8) menu_vm "$NODE" ;;
            9) manage_node_system "$NODE"; pause_action ;;
            10) manage_services "$NODE"; pause_action ;;
            11) view_node_syslog "$NODE"; pause_action ;;
            12) download_to_storage "$NODE"; pause_action ;;
            13) manage_backup_files "$NODE"; pause_action ;;
            14) bulk_power "$NODE"; pause_action ;;
            b|B|q|Q|0) return ;;
            *) echo "Invalid option"; pause_action ;;
        esac
    done
}

get_credentials
authenticate

while true; do
    clear
    echo -e "\n${GREEN}=== PROXMOX API MASTER PANEL V1.0 ===${NC}"
    echo -e "${WHITE}[ CLUSTER & RESOURCES ]${NC}"
    echo "1. Live Performance Dashboard (VM & LXC)"
    echo "2. Cluster Task Log (Detailed)"
    echo "3. Access Control (Users, Groups, Realms)"
    echo "4. HA & Replication"
    echo "5. Backup Schedule Jobs"
    echo "6. SDN (Zones/VNets)"
    echo "7. Resource Pools"
    echo "8. API Generator (Delegation)"
    echo "9. Global Storage Config (Add/Remove)"
    echo "10. Ceph Status & OSDs"
    echo "11. Cluster Firewall & Aliases"
    echo "12. Cluster Join Info"
    echo "13. Metric Servers (InfluxDB)"
    echo "14. Notifications"
    echo "15. Cluster Corosync/Quorum"
    echo "16. Proxmox Version Info"
    echo -e "${WHITE}[ NODE INFRASTRUCTURE ]${NC}"
    echo "17. Select Node to Manage (Disks, Backups, Hardware, VMs...)"
    echo "18. Raw API Console"
    echo "0. Exit"
    
    read -p "Select Option: " MAIN_OPT
    case $MAIN_OPT in
        1) live_dashboard ;;
        2) view_cluster_log; pause_action ;;
        3) manage_users; manage_groups_roles; manage_auth_realms; pause_action ;;
        4) view_ha_status; manage_replication; pause_action ;;
        5) manage_backup_jobs; pause_action ;;
        6) manage_sdn; pause_action ;;
        7) manage_pools; pause_action ;;
        8) create_advanced_api; pause_action ;;
        9) manage_storage_cfg; pause_action ;;
        10) manage_ceph; pause_action ;;
        11) manage_cluster_firewall; pause_action ;;
        12) get_join_info; pause_action ;;
        13) manage_metric_servers; pause_action ;;
        14) manage_notifications; pause_action ;;
        15) check_cluster_quorum; pause_action ;;
        16) check_pve_version; pause_action ;;
        17) 
           echo "Nodes: $(list_nodes)"
           read -p "Target Node: " SEL_NODE
           menu_node "$SEL_NODE"
           ;;
        18)
            read -p "Method: " M; read -p "Endpoint: " E; read -p "Data: " D
            pve_api "$M" "$E" "$D" | jq .
            pause_action
            ;;
        0|q|Q) exit 0 ;;
        *) echo "Invalid"; pause_action ;;
    esac
done
