# Driver that supports multiple loopbacks in Linux system
This driver is adding more loopback interfaces in the Linux systems. When you are using your Linux system as a router you will face the necessity to add more loopback interfaces.
By default Linux offers only one loopback interface, ```lo``. 

When you are adding a new VRF in the system:

```
ip link add VPN type vrf table 2
```

It will create an interface called ```VPN``` and it can be used as loopback for that VRF. Then you can bind interfaces under this VRF and all the traffic will be forwarded into ```table 10```.

But there are situations that you need one or more loopbacks in the default VRF of in other VRF. For example is a loopback for OSPF and another loopback to be used in BGP connections or just to be used as a route test distribution or to bind some services like SSH on that loopback.

The ```dummy``` driver can be used as an addtional loopback, but is failing if you are using it as a source or if you are trying to ping the IP of the dummy interface which resides in a VRF.

Let's take this example:

```
ip link add internet type vrf table 2
ip link set internet up
ip route add blackhole default metric 4278198272 table 2
```
We just created a new VRF called ```internet``` using the forwarding table 2.

Then let's add some dummy interfaces:
```
ip link add lo0 type dummy
ip link set lo0 up

ip link add lo1 type dummy
ip link set lo1 master internet
ip link set lo1 up
```

Then we will create some route-leaks between default VRF (called also GRT - Global Routing Table) and this VRF ```internet``` using FRRouting **VPN MP-BGP**. 
Keep in mind that **we are doing route-leak using VPN BGP**, not just simple BGP VRF route-leak. There are two different methods to achive this using FRR BGP. My setup is used for more complex setups to be able to export via MPLS and MP-BGP the VRFs to other routers in the network, for this reason I'm using VPN local route-leak.

Example of **FRRouting BGP VPN** route-leak:
```
frr defaults traditional
hostname RouterFW
log syslog informational
ip forwarding
ipv6 forwarding
service integrated-vtysh-config
!
interface lo
 ip address 10.0.0.1/32
exit
!
interface lo0
 ip address 10.0.0.2/32
exit
!
interface internet
 ip address 10.2.0.1/32
exit
!
interface lo1
 ip address 10.2.0.2/32
exit
!
router bgp 65500
 bgp router-id 10.0.0.1
 !
 address-family ipv4 unicast
  redistribute connected route-map VPN-GRT-connected
  rd vpn export 65500:11000
  rt vpn import 65500:11100 65500:10000 65500:10100
  rt vpn export 65500:11000
  export vpn
  import vpn
 exit-address-family
exit
!
router bgp 65500 vrf internet
 bgp router-id 10.2.0.1
 !
 address-family ipv4 unicast
  redistribute connected route-map VPN-internet-connected
  rd vpn export 65500:10000
  rt vpn import 65500:10000 65500:10100 65500:11100
  rt vpn export 65500:10000
  export vpn
  import vpn
 exit-address-family
exit
!
route-map VPN-internet-connected permit 1000
 set extcommunity rt 65500:10100
exit
!
route-map VPN-GRT-connected permit 1000
 set extcommunity rt 65500:11100
exit
```

Short explanation:
1. **router bgp 65500 -> address-family ipv4 unicast** is exporting the default VRF to VPN with extcommunity 65500:11000 and importing VPN to VRF routes with extcommunity 65500:11100 65500:10000 **65500:10100**.
2. We will apply extcommunity **65500:11100** to all connected routes that are redistributed in BGP table in default VRF.
3. **router bgp 65500 vrf internet -> address-family ipv4 unicast** is exporting the default VRF to VPN with extcommunity 65500:10100 and importing VPN to VRF routes with extcommunity 65500:10000 65500:10100 **65500:11100**.
4. We will apply extcommunity **65500:10100** to all connected routes that are redistributed in BGP table in default VRF.
So default will import all connected routes from VRF ```internet``` and ```internet``` VRF will import all connected routes from default.

Then we should be able to see this output:
```
# show ip route
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

K>* 0.0.0.0/0 [0/0] via 89.X.X.193, eth0 onlink, 00:35:45
C>* 10.0.0.1/32 is directly connected, lo, 00:34:46
C>* 10.0.0.2/32 is directly connected, lo0, 00:29:40
B>* 10.2.0.1/32 [20/0] is directly connected, internet (vrf internet), weight 1, 00:29:26
B>* 10.2.0.2/32 [20/0] is directly connected, lo1 (vrf internet), weight 1, 00:29:17
C>* 89.X.X.192/26 is directly connected, eth0, 00:35:45

# show ip route vrf internet
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

VRF internet:
K>* 0.0.0.0/0 [255/8192] unreachable (blackhole), 00:11:45
B>* 10.0.0.1/32 [20/0] is directly connected, lo (vrf default), weight 1, 00:32:54
B>* 10.0.0.2/32 [20/0] is directly connected, lo0 (vrf default), weight 1, 00:30:05
C>* 10.2.0.1/32 is directly connected, internet, 00:29:52
C>* 10.2.0.2/32 is directly connected, lo1, 00:29:42
B>* 89.X.X.192/26 [20/0] is directly connected, eth0 (vrf default), weight 1, 00:32:54
```

As you can see the default / GRT (Global Routing Table) routes are visible in ```internet``` VRF and vice-versa.
So if we will ping the IP addresses of ```lo``` and ```internet``` interfaces it should work.

```
# ping -c 1 10.2.0.1 -I 10.0.0.1
PING 10.2.0.1 (10.2.0.1) from 10.0.0.1 : 56(84) bytes of data.
64 bytes from 10.2.0.1: icmp_seq=1 ttl=64 time=0.054 ms

--- 10.2.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.054/0.054/0.054/0.000 ms

# ip vrf exec internet ping 10.0.0.1 -I 10.2.0.1 -c 1
PING 10.0.0.1 (10.0.0.1) from 10.2.0.1 : 56(84) bytes of data.
64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.037 ms

--- 10.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.037/0.037/0.037/0.000 ms

```

Also is working if I'm using as source ```dummy``` interface ```lo0``` from default VRF to any address in VRF:
```
# ping -c 1 10.2.0.1 -I 10.0.0.1
PING 10.2.0.1 (10.2.0.1) from 10.0.0.1 : 56(84) bytes of data.
64 bytes from 10.2.0.1: icmp_seq=1 ttl=64 time=0.071 ms

--- 10.2.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.071/0.071/0.071/0.000 ms

# ping -c 1 10.2.0.1 -I 10.0.0.2
PING 10.2.0.1 (10.2.0.1) from 10.0.0.2 : 56(84) bytes of data.
64 bytes from 10.2.0.1: icmp_seq=1 ttl=64 time=0.049 ms

--- 10.2.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.049/0.049/0.049/0.000 ms
```

But if I'm trying to ping from the ```dummy``` interface in VRF from anything in default VRF not working anymore:
```
# ping -c 1 10.2.0.2 -I 10.0.0.1 -w 1
PING 10.2.0.2 (10.2.0.2) from 10.0.0.1 : 56(84) bytes of data.

--- 10.2.0.2 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms

# ping -c 1 10.2.0.2 -I 10.0.0.2 -w 1
PING 10.2.0.2 (10.2.0.2) from 10.0.0.2 : 56(84) bytes of data.

--- 10.2.0.2 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms
```

Also if we are trying to use as source for the ```dummy``` interface from VRF ```internet``` and ping anything in default vrf is not working:

```
# ip vrf exec internet ping 10.0.0.1 -I 10.2.0.2 -c 1 -w 1
PING 10.0.0.1 (10.0.0.1) from 10.2.0.2 : 56(84) bytes of data.

--- 10.0.0.1 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms

# ip vrf exec internet ping 10.0.0.2 -I 10.2.0.2 -c 1 -w 1
PING 10.0.0.2 (10.0.0.2) from 10.2.0.2 : 56(84) bytes of data.

--- 10.0.0.2 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms

# ip vrf exec internet ping 89.X.X.252 -I 10.2.0.2 -c 1 -w 1
PING 89.X.X.252 (89.X.X.252) from 10.2.0.2 : 56(84) bytes of data.

--- 89.X.X.252 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms

```

Adding this driver, based on dummy interface combined with VRF interface we will be able to use it as a normal loopback.

First detele the old interfaces loX:
```
ip link del lo1
ip link del lo0
```

Build this driver:
```
git clone https://github.com/EasyNetDev/linux-multi-loopback
cd linux-multi-loopback
make
insmod lo.ko numloopbacks=4
```

You will have 4 loopbacks called lo0, lo1, lo2 and lo3:
```
26: lo0: <NOARP,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/ether 76:77:30:25:d8:40 brd ff:ff:ff:ff:ff:ff
27: lo1: <NOARP,UP,LOWER_UP> mtu 65536 qdisc noqueue master internet state UNKNOWN mode DEFAULT group default qlen 1000
    link/ether 56:64:44:43:3c:04 brd ff:ff:ff:ff:ff:ff
28: lo2: <NOARP,UP,LOWER_UP> mtu 65536 qdisc noqueue master internet state UNKNOWN mode DEFAULT group default qlen 1000
    link/ether ca:14:15:a2:af:24 brd ff:ff:ff:ff:ff:ff
29: lo3: <NOARP> mtu 65536 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether ee:e1:4c:89:de:2a brd ff:ff:ff:ff:ff:ff
```

Let's move lo1 in the ```internet``` vrf:

```
ip link set lo1 master internet
```

Let's do the test pings which failed previously:
```
# ping 10.2.0.2 -I 10.0.0.1 -c 1 -w 1
PING 10.2.0.2 (10.2.0.2) from 10.0.0.1 : 56(84) bytes of data.
64 bytes from 10.2.0.2: icmp_seq=1 ttl=64 time=0.048 ms

--- 10.2.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.048/0.048/0.048/0.000 ms

# ping 10.2.0.2 -I 10.0.0.2 -c 1 -w 1
PING 10.2.0.2 (10.2.0.2) from 10.0.0.2 : 56(84) bytes of data.
64 bytes from 10.2.0.2: icmp_seq=1 ttl=64 time=0.043 ms

--- 10.2.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.043/0.043/0.043/0.000 ms
```

Then from the vrf ```internet```:

```
# ip vrf exec internet ping 89.X.X.252 -I 10.2.0.2 -c 1 -w 1
ping: 89.X.X.252: Name or service not known
root@RouterFW:/opt/devel/frrouting# ip vrf exec internet ping 10.0.0.1 -I 10.2.0.2 -c 1 -w 1
PING 10.0.0.1 (10.0.0.1) from 10.2.0.2 : 56(84) bytes of data.
64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.062 ms

--- 10.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.062/0.062/0.062/0.000 ms
root@RouterFW:/opt/devel/frrouting# ip vrf exec internet ping 10.0.0.2 -I 10.2.0.2 -c 1 -w 1
PING 10.0.0.2 (10.0.0.2) from 10.2.0.2 : 56(84) bytes of data.
64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=0.046 ms

--- 10.0.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.046/0.046/0.046/0.000 ms
root@RouterFW:/opt/devel/frrouting# ip vrf exec internet ping 89.X.X.252 -I 10.2.0.2 -c 1 -w 1
PING 89.X.X.252 (89.X.X.252) from 10.2.0.2 : 56(84) bytes of data.
64 bytes from 89.X.X.252: icmp_seq=1 ttl=64 time=0.045 ms

--- 89.X.X.252 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.045/0.045/0.045/0.000 ms
```

THAT'S IT! Is working!!

