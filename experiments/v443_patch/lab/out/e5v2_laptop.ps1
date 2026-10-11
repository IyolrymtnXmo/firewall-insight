# Run on YOUR LAPTOP (VPN to the lab) in PowerShell. Then run:  python experiments/v443_patch/lab/e5_lab.py logs --minutes 20
"laptop addresses: $((Get-NetIPAddress -AddressFamily IPv4 | ? { $_.IPAddress -notlike '127.*' }).IPAddress -join ', ')"

"===== L1 Laptop ping to a VLAN10 address (explicit ICMP rule 10)  $(Get-Date -Format o)"
ping -n 2 192.168.10.50

"===== L2 Laptop RDP to the RDP server address (rule 8)  $(Get-Date -Format o)"
Test-NetConnection 192.168.20.100 -Port 3389 -WarningAction SilentlyContinue | Select ComputerName,RemotePort,TcpTestSucceeded

"===== L3 Laptop HTTPS to the web server address (rule 9)  $(Get-Date -Format o)"
Test-NetConnection 192.168.20.20 -Port 443 -WarningAction SilentlyContinue | Select ComputerName,RemotePort,TcpTestSucceeded

"===== L4 Laptop LDAP to the AD address  $(Get-Date -Format o)"
Test-NetConnection 192.168.10.10 -Port 389 -WarningAction SilentlyContinue | Select ComputerName,RemotePort,TcpTestSucceeded

"===== L5 Laptop SMB to a VLAN10 address (cleanup expected)  $(Get-Date -Format o)"
Test-NetConnection 192.168.10.50 -Port 445 -WarningAction SilentlyContinue | Select ComputerName,RemotePort,TcpTestSucceeded

"===== L6 Laptop HTTPS to the cluster VIP (gateway endpoint, implied web-admin rule First)  $(Get-Date -Format o)"
Test-NetConnection 172.23.31.179 -Port 443 -WarningAction SilentlyContinue | Select ComputerName,RemotePort,TcpTestSucceeded

"===== L7 Laptop ping to the cluster VIP (gateway endpoint)  $(Get-Date -Format o)"
ping -n 2 172.23.31.179

"===== L8 Laptop TCP 8081 to a VLAN20 address (cleanup expected)  $(Get-Date -Format o)"
Test-NetConnection 192.168.20.100 -Port 8081 -WarningAction SilentlyContinue | Select ComputerName,RemotePort,TcpTestSucceeded
