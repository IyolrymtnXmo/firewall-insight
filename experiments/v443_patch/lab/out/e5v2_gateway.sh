# Run on the ACTIVE member of External-Cluster, expert mode.
# First check the syntax your build accepts:  fw up_execute 2>&1 | head -40
# Then run everything at once and paste the whole output back:
#   bash e5v2_gateway.sh 2>&1 | tee /var/log/e5v2_upexec.txt

echo "===== O1 VLAN10 reaches the RDP server"
fw up_execute mode=access in_ifn=eth1 ipp=6 src=192.168.10.50 dst=192.168.20.100 dport=3389

echo "===== O2 VLAN20 cannot reach the RDP server"
fw up_execute mode=access in_ifn=eth1 ipp=6 src=192.168.20.50 dst=192.168.20.100 dport=3389

echo "===== O3 VLAN20 reaches AD over LDAP"
fw up_execute mode=access in_ifn=eth1 ipp=6 src=192.168.20.50 dst=192.168.10.10 dport=389

echo "===== O4 VLAN10 cannot reach AD over LDAP"
fw up_execute mode=access in_ifn=eth1 ipp=6 src=192.168.10.50 dst=192.168.10.10 dport=389

echo "===== O5 Lab hosts reach the web server"
fw up_execute mode=access in_ifn=eth1 ipp=6 src=192.168.10.50 dst=192.168.20.20 dport=443

echo "===== O6 Lab hosts browse the internet (Inline Layer)"
fw up_execute mode=access in_ifn=eth1 ipp=6 src=192.168.10.50 dst=8.8.8.8 dport=443

echo "===== O7 Lab hosts cannot SMB to the Management Server"
fw up_execute mode=access in_ifn=eth1 ipp=6 src=192.168.10.50 dst=172.23.31.180 dport=445

echo "===== O8 The internet cannot reach a lab client"
fw up_execute mode=access in_ifn=eth2 ipp=6 src=8.8.8.8 dst=192.168.10.50 dport=3389

echo "===== O9 VLAN20 to AD on a high port (DCE-RPC rule)"
fw up_execute mode=access in_ifn=eth1 ipp=6 src=192.168.20.50 dst=192.168.10.10 dport=9999

echo "===== N1 ICMP echo to VLAN31 infrastructure (explicit ICMP rule)"
fw up_execute mode=access in_ifn=eth1 ipp=1 src=192.168.10.50 dst=172.23.31.254 type=8 code=0

echo "===== N2 ICMP echo to the internet: no explicit rule, implied 'Accept ICMP requests' (Before Last)"
fw up_execute mode=access in_ifn=eth1 ipp=1 src=192.168.10.50 dst=8.8.8.8 type=8 code=0

echo "===== N5 HTTPS to the internet through the Inline Layer"
fw up_execute mode=access in_ifn=eth1 ipp=6 src=192.168.10.50 dst=1.1.1.1 dport=443

echo "===== N6 DNS over UDP to the internet (Inline Layer or implied DNS rule)"
fw up_execute mode=access in_ifn=eth1 ipp=17 src=192.168.10.50 dst=8.8.8.8 dport=53

echo "===== N7 NTP to the internet through the Inline Layer"
fw up_execute mode=access in_ifn=eth1 ipp=17 src=192.168.10.50 dst=216.239.35.0 dport=123

echo "===== N8 SMB to the outer segment falls to the cleanup rule"
fw up_execute mode=access in_ifn=eth1 ipp=6 src=192.168.10.50 dst=172.23.34.254 dport=445

echo "===== N9 Source-port service, source port inside its range"
fw up_execute mode=access in_ifn=eth1 ipp=6 src=192.168.10.50 dst=1.1.1.1 dport=8081 sport=40050

echo "===== N10 Source-port service, source port outside its range"
fw up_execute mode=access in_ifn=eth1 ipp=6 src=192.168.10.50 dst=1.1.1.1 dport=8081 sport=50050

echo "===== N11 Rule limited by an expired Time object"
fw up_execute mode=access in_ifn=eth1 ipp=6 src=192.168.10.50 dst=1.1.1.1 dport=8082

echo "===== N12 Rule with Install On = External-Cluster"
fw up_execute mode=access in_ifn=eth1 ipp=6 src=192.168.10.50 dst=1.1.1.1 dport=8083

echo "===== N13 IPv6 source on a dual-stack host object"
fw6 up_execute in_ifn=eth1 ipp=6 src=2001:db8:10::51 dst=2001:db8:20::100 dport=22

echo "===== N14 IPv6 source outside the rule"
fw6 up_execute in_ifn=eth1 ipp=6 src=2001:db8:10::52 dst=2001:db8:20::100 dport=22

echo "===== N15 HTTPS to the cluster address (gateway endpoint)"
fw up_execute mode=access in_ifn=eth1 ipp=6 src=192.168.10.50 dst=172.23.31.179 dport=443

echo "===== N16 ICMP echo to the cluster address (gateway endpoint)"
fw up_execute mode=access in_ifn=eth1 ipp=1 src=192.168.10.50 dst=172.23.31.179 type=8 code=0

echo "===== N17 ICMP echo from outside to a lab address: only the cleanup rule and the implied ICMP rule (Before Last) match"
fw up_execute mode=access in_ifn=eth2 ipp=1 src=8.8.8.8 dst=192.168.10.50 type=8 code=0
