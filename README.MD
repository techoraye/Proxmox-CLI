# Proxmox Automation & Management Script

A comprehensive bash-based management tool for Proxmox VE clusters, providing full control over your virtual infrastructure through the Proxmox API.

![Version](https://img.shields.io/badge/version-1.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Proxmox](https://img.shields.io/badge/Proxmox-VE-orange)

## 🚀 Features

### Cluster Management
- **Live Performance Dashboard** - Real-time monitoring of nodes, VMs, and containers
- **Task Log Viewer** - Track all cluster operations with detailed UPID logs
- **HA & Replication** - High availability status and ZFS replication management
- **Backup Scheduling** - Manage automated backup jobs across the cluster
- **Corosync/Quorum** - Monitor cluster health and quorum status

### Access Control & Security
- **User Management** - Create, modify, and manage Proxmox users
- **Groups & Roles** - Configure permission groups and role assignments
- **Authentication Realms** - LDAP/AD integration and sync
- **API Token Generator** - Create delegated API tokens with specific permissions
- **Cluster Firewall** - Manage security groups, aliases, and policies

### Virtual Machine Operations
- **Power Control** - Start, stop, shutdown, reset, and reboot VMs
- **Hardware Management** - Adjust CPU cores, RAM, and resources
- **Cloud-Init Configuration** - Set users, passwords, and network settings
- **Snapshot Management** - Create and manage VM snapshots
- **Migration** - Live migrate VMs between nodes
- **Cloning** - Full VM cloning with customization
- **Template Conversion** - Convert VMs to reusable templates
- **USB Passthrough** - Attach USB devices to VMs
- **VNC Access** - Generate VNC tickets for remote console access

### Container (LXC) Operations
- **Container Creation** - Deploy new LXC containers from templates
- **Resource Management** - Modify CPU, RAM, swap, and disk allocations
- **Network Configuration** - Set static IPs, DHCP, and gateway settings
- **DNS Configuration** - Manage hostname and nameservers
- **Container Cloning** - Duplicate containers quickly
- **Template Conversion** - Convert containers to templates
- **Snapshot Support** - Create container snapshots

### Node Infrastructure
- **System Status** - View node health, uptime, and resource usage
- **Network Interfaces** - Monitor and configure network adapters
- **Disk Management** - View disks, ZFS pools, and LVM volumes
- **APT Management** - Check for updates and manage repositories
- **Hardware Information** - List PCI and USB devices for passthrough
- **Certificate Management** - View SSL certificate details
- **Service Control** - Start, stop, and restart system services
- **System Logs** - View recent syslog entries
- **Backup Management** - Restore, delete, and manage backup files
- **Bulk Operations** - Start or stop all VMs/containers at once

### Storage & Networking
- **Global Storage Config** - Add/remove Directory, NFS, and other storage types
- **SDN Management** - Software Defined Networking zones and VNets
- **Resource Pools** - Organize resources into logical groups
- **ISO/Template Downloads** - Download images directly from URLs
- **Ceph Integration** - Monitor Ceph cluster status and OSDs

### Monitoring & Metrics
- **Metric Servers** - Configure InfluxDB and other metric collectors
- **Notifications** - Manage notification targets and matchers (PVE 8.1+)
- **Cluster Join Info** - Retrieve information for adding new nodes

## 📋 Requirements

- **Proxmox VE** - Version 6.0 or higher (optimized for 8.x)
- **Bash** - Version 4.0 or higher
- **jq** - JSON processor for parsing API responses
- **curl** - For making HTTP requests to the Proxmox API

### Installing Dependencies

```bash
# Debian/Ubuntu/Proxmox
sudo apt-get update
sudo apt-get install jq curl

# RHEL/CentOS
sudo yum install jq curl
```

## 🔧 Installation

1. Download the script:
```bash
wget https://raw.githubusercontent.com/techoraye/Proxmox-CLI/refs/heads/main/Proxmox-CLI.sh
# or
curl -O https://raw.githubusercontent.com/techoraye/Proxmox-CLI/refs/heads/main/Proxmox-CLI.sh
```

2. Make it executable:
```bash
chmod +x proxmox-manager.sh
```

3. Run the script:
```bash
./Proxmox-CLI.sh
```

## 🎯 Usage

### Basic Usage

Run the script and follow the interactive prompts:

```bash
./Proxmox-CLI.sh
```

On first run, you'll be prompted for:
- **Proxmox Host** - IP address or FQDN of your Proxmox server
- **Username** - Default is `root@pam`
- **Password** - Will not be echoed to the screen

### Using Environment Variables

You can pre-configure credentials using environment variables:

```bash
export PVE_HOST="192.168.1.100"
export PVE_USER="root@pam"
export PVE_PASS="your-password"

./proxmox-manager.sh
```

### Example Workflows

**Creating a New LXC Container:**
1. Select option 17 (Select Node to Manage)
2. Choose option 8 (Manage VMs/CTs)
3. Select option 13 (Create New LXC)
4. Follow the prompts to configure your container

**Migrating a VM:**
1. Select option 17 (Select Node to Manage)
2. Choose option 8 (Manage VMs/CTs)
3. Select option 4 (Migrate)
4. Enter the VM ID and target node

**Monitoring Cluster Performance:**
1. Select option 1 (Live Performance Dashboard)
2. View real-time stats (press 'q' to exit)

## 🔐 Security Considerations

- **Never commit credentials** - Use environment variables or interactive input
- **API Tokens** - Consider using API tokens instead of passwords for automation
- **HTTPS** - The script uses `-k` flag with curl (insecure). For production, configure proper SSL certificates
- **Principle of Least Privilege** - Create dedicated API users with minimal required permissions
- **Audit Logs** - All actions are logged in Proxmox task history

### Creating a Dedicated API User

```bash
# Use option 8 (API Generator) to create restricted API tokens
# Or manually through the web UI:
# Datacenter → Permissions → Users → Add
```

## 🐛 Troubleshooting

### Authentication Fails
```bash
# Verify credentials
curl -k -d "username=root@pam" --data-urlencode "password=yourpass" \
  https://your-proxmox-host:8006/api2/json/access/ticket
```

### jq Not Found
```bash
sudo apt-get install jq
```

### Connection Refused
- Check that Proxmox is running: `systemctl status pveproxy`
- Verify firewall allows port 8006
- Confirm hostname/IP is correct

### Permission Denied
- Ensure user has required privileges
- Check ACL permissions in Proxmox web UI
- Verify realm is correct (e.g., `@pam` vs `@pve`)

## 📚 API Reference

This script is based on the official Proxmox VE API:
- [API Viewer](https://pve.proxmox.com/pve-docs/api-viewer/)
- [API Documentation](https://pve.proxmox.com/wiki/Proxmox_VE_API)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## 📝 License

This project is licensed under the MIT License.

## ⚠️ Disclaimer

This script interacts directly with the Proxmox API and can make destructive changes to your infrastructure. Always:
- Test in a development environment first
- Keep backups of critical VMs and data
- Review commands before execution
- Use at your own risk

## 🙏 Credits

**Created by:** Techoraye  
**Based on:** Proxmox VE API  
**Version:** 1.0

---

**Happy Virtualizing! 🚀**
