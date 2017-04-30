sudo ip tuntap add dev tun1 mode tun
sudo ip addr add 127.1.0.1/16 dev tun1
sudo ip link set tun1 up
sudo ip route change 127.1.0.0/16 via 127.1.0.1
sudo ifconfig lo netmask 255.255.0.0

