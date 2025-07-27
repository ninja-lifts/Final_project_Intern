# Save the .py file in home Directory(Audit_Report.pdf will be stored in the same directory) 

## Ensure Prerequisites
  ### Confirm iptables is installed and available.
  ### Ensure sshd is present for SSH configuration checks.

## Enable iptabes after instllation 
 ```
   sudo apt install iptables
   sudo systemctl enable iptables
 ```

## Install rkhunter for rootkit detection:
```
sudo apt install rkhunter    # Debian/Ubuntu
sudo yum install rkhunter    # RHEL/CentOS
```

## Make the Script Executable
```
chmod +x linux_audit.py
```

## Run the Audit and Run the script with root privileges to access all checks:
```
sudo ./linux_audit.py
```

  ### The tool will display a summary report in your terminal.

  ### A detailed results file will be saved in the same directory, named like:
    ./hardening-report-YYYY-MM-DD.txt
 
## Notes
  ### This script checks firewall (CIS 3.5), SSH settings (CIS 5.2), and rootkit hygiene.

  ### The check_services_cis function is under development (future update).

  ### Use it alongside tools like OpenVAS for deeper vulnerability scanning.
