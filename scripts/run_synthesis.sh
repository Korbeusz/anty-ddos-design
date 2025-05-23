python3 /home/mati/mur/mur/final_build/parsercmsvol_module.py
sed -i 's/top/antyddos/g' $PWD/parsercmsvol_module.v
sed -i '658,$d' /home/mati/mur/mur/final_build/alt_e100s10.v
cat $PWD/parsercmsvol_module.v >> /home/mati/mur/mur/final_build/alt_e100s10.v
rm $PWD/parsercmsvol_module.v $PWD/parsercmsvol_module.v.json
nmcli connection up id uwr_vpn passwd-file ~/.uwr_vpn.pass
scp /home/mati/mur/mur/final_build/alt_e100s10.v mbilyk@192.168.4.13:/home/mbilyk/anty-ddos/hardware_test_design
ssh mbilyk@192.168.4.13 "nohup /opt/intelFPGA_pro/24.2/quartus/bin/quartus_sh --flow compile /home/mbilyk/anty-ddos/hardware_test_design/alt_e100s10.qpf -c alt_e100s10.qsf > /home/mbilyk/anty-ddos/last_synth.log 2>&1 &" 
nmcli connection down id uwr_vpn