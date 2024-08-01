from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.cli import CLI

class CustomTopo(Topo):
    def __init__(self):
        super(CustomTopo, self).__init__()

        # 创建交换机
        sA = self.addSwitch('sA', dpid='00:00:00:00:00:00:00:01')
        sB = self.addSwitch('sB', dpid='00:00:00:00:00:00:00:02')
        sC = self.addSwitch('sC', dpid='00:00:00:00:00:00:00:03')
        sD = self.addSwitch('sD', dpid='00:00:00:00:00:00:00:04')

        # 创建主机
        h1 = self.addHost('h1', ip='10.0.0.1')
        h2 = self.addHost('h2', ip='10.0.0.2')
        h3 = self.addHost('h3', ip='10.0.0.3')

        # 创建链路
        self.addLink(h1, sA, bw=10, delay='5ms', loss=1, use_htb=True)
        self.addLink(h2, sA, bw=10, delay='5ms', loss=1, use_htb=True)
        self.addLink(sA, sB, bw=10, delay='5ms', loss=1, use_htb=True)
        self.addLink(sA, sC, bw=10, delay='5ms', loss=1, use_htb=True)
        self.addLink(sB, sD, bw=10, delay='5ms', loss=1, use_htb=True)
        self.addLink(sC, sD, bw=10, delay='5ms', loss=1, use_htb=True)
        self.addLink(h3, sD, bw=10, delay='5ms', loss=1, use_htb=True)

topos = {"customtopo": (lambda: CustomTopo())}

def run_custom_topology():
    topo = CustomTopo()
    net = Mininet(topo=topo, link=TCLink, controller=None, autoSetMacs=True, autoStaticArp=True)
    net.addController('controller', controller=RemoteController, ip='127.0.0.1', port=6633, protocols="OpenFlow13")
    net.start()

    # 打印每个交换机的DPID
    print("\n交换机DPID:")
    for switch in net.switches:
        print(f"{switch.name}: {switch.dpid}")

    # 打印每个主机的IP
    print("\n主机IP:")
    for host in net.hosts:
        print(f"{host.name}: {host.IP()}")

    # 打印连接情况
    dumpNodeConnections(net.hosts)

    CLI(net)
    net.stop()

if __name__ == '__main__':
    run_custom_topology()

