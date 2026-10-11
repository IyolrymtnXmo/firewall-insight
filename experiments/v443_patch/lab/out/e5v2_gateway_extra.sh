echo "===== N17 ICMP echo from outside to a lab address: only the cleanup rule and the implied ICMP rule (Before Last) match"
fw up_execute mode=access in_ifn=eth2 ipp=1 src=8.8.8.8 dst=192.168.10.50 type=8 code=0
