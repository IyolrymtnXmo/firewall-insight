# Run on Client-01 (192.168.10.50) in PowerShell. Paste the whole output back.
function SPORT($p, $ip, $port) {
  $c = New-Object System.Net.Sockets.TcpClient([System.Net.IPEndPoint]::new([ipaddress]::Any, [int]$p))
  $t = $c.ConnectAsync($ip, [int]$port); $ok = $t.Wait(4000)
  "sport=$p -> ${ip}:$port connected=$($c.Connected) finished=$ok"; $c.Close() }

"===== N2 ICMP echo to the internet (no explicit rule; implied ICMP rule?)  $(Get-Date -Format o)"
ping -n 3 8.8.8.8

"===== N5 HTTPS to the internet through the Inline Layer  $(Get-Date -Format o)"
Test-NetConnection 1.1.1.1 -Port 443

"===== N6 DNS over UDP to the internet (Inline Layer or implied DNS rule)  $(Get-Date -Format o)"
Resolve-DnsName example.com -Server 8.8.8.8 -DnsOnly

"===== N7 NTP to the internet through the Inline Layer  $(Get-Date -Format o)"
w32tm /stripchart /computer:216.239.35.0 /samples:2 /dataonly

"===== N8 SMB to the outer segment falls to the cleanup rule  $(Get-Date -Format o)"
Test-NetConnection 172.23.34.254 -Port 445

"===== N9 Source-port service, source port inside its range  $(Get-Date -Format o)"
SPORT 40050 1.1.1.1 8081

"===== N10 Source-port service, source port outside its range  $(Get-Date -Format o)"
SPORT 50050 1.1.1.1 8081

"===== N11 Rule limited by an expired Time object  $(Get-Date -Format o)"
Test-NetConnection 1.1.1.1 -Port 8082

"===== N12 Rule with Install On = External-Cluster  $(Get-Date -Format o)"
Test-NetConnection 1.1.1.1 -Port 8083

"===== N15 HTTPS to the cluster address (gateway endpoint)  $(Get-Date -Format o)"
Test-NetConnection 172.23.31.179 -Port 443

"===== N16 ICMP echo to the cluster address (gateway endpoint)  $(Get-Date -Format o)"
ping -n 3 172.23.31.179
