nmcli connection up stud.ii
sudo ip route add 192.168.4.0/24 dev ppp0 
sudo ip route del default dev ppp0 
export STRATIX=192.168.4.13

