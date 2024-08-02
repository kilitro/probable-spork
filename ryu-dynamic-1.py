from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, ether_types
import os


class DynamicBandwidth(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynamicBandwidth, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.sA_dpid = '00:00:00:00:00:00:00:01'
        self.sB_dpid = '00:00:00:00:00:00:00:02'
        self.sC_dpid = '00:00:00:00:00:00:00:03'
        self.sD_dpid = '00:00:00:00:00:00:00:04'
        self.h1_port = 1
        self.h2_port = 2
        self.video_packet_count = 0
        self.total_packet_count = 0
        self.packet_count = 0  # 增加包计数器
        self.sb_packets = 0  # sB 的包计数
        #self.sb_tx_packets = 0  # sB 发送的包计数
        self.sc_packets = 0  # sC 的包计数
        #self.sc_tx_packets = 0  # sC 发送的包计数
        self.sb_target_port = 1  # sB要统计的端口号
        self.sc_target_port = 1  # sC要统计的端口号


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        self.logger.info(f"Switch {datapath.id} connected")

        if datapath.id == int(self.sA_dpid.replace(':', ''), 16):
            self.setup_sa_flows(datapath)
        elif datapath.id == int(self.sB_dpid.replace(':', ''), 16):
            self.setup_sb_flows(datapath)
        elif datapath.id == int(self.sC_dpid.replace(':', ''), 16):
            self.setup_sc_flows(datapath)
        elif datapath.id == int(self.sD_dpid.replace(':', ''), 16):
            self.setup_sd_flows(datapath)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority,
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info(f"Added flow to switch {datapath.id}: priority={priority}, match={match}, actions={actions}")

    def setup_sb_flows(self, datapath):
        parser = datapath.ofproto_parser
        # 优先转发视频流量
        match_video = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=80)  # HTTP 流量
        actions_video = [parser.OFPActionOutput(1)]
        self.add_flow(datapath, 10, match_video, actions_video)

        match_video_https = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=443)  # HTTPS 流量
        actions_video_https = [parser.OFPActionOutput(1)]
        self.add_flow(datapath, 10, match_video_https, actions_video_https)

        # 转发其他流量
        match = parser.OFPMatch(eth_type=0x0800)
        actions = [parser.OFPActionOutput(1)]
        self.add_flow(datapath, 1, match, actions)

        match = parser.OFPMatch(ipv4_dst='10.0.0.3', eth_type=0x0800)
        actions = [parser.OFPActionOutput(2)]
        self.add_flow(datapath, 1, match, actions)

    def setup_sc_flows(self, datapath):
        parser = datapath.ofproto_parser
        # 连接 sA 和 sD 的流量
        match = parser.OFPMatch(ipv4_dst='10.0.0.1', eth_type=0x0800)
        actions = [parser.OFPActionOutput(1)]
        self.add_flow(datapath, 1, match, actions)

        match = parser.OFPMatch(ipv4_dst='10.0.0.2', eth_type=0x0800)
        actions = [parser.OFPActionOutput(1)]
        self.add_flow(datapath, 1, match, actions)

        match = parser.OFPMatch(ipv4_dst='10.0.0.3', eth_type=0x0800)
        actions = [parser.OFPActionOutput(2)]
        self.add_flow(datapath, 1, match, actions)

    def setup_sd_flows(self, datapath):
        parser = datapath.ofproto_parser
        # 设置流表规则 视频流量: sA -> sB -> sD
        match_video_http = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=80)
        actions_video_http = [parser.OFPActionOutput(1)]
        self.add_flow(datapath, 10, match_video_http, actions_video_http)

        match_video_https = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=443)
        actions_video_https = [parser.OFPActionOutput(1)]
        self.add_flow(datapath, 10, match_video_https, actions_video_https)

        # 设置非视频流量流表规则
        match_other = parser.OFPMatch(eth_type=0x0800, ipv4_dst='10.0.0.1')
        actions_other = [parser.OFPActionOutput(2)]
        self.add_flow(datapath, 1, match_other, actions_other)

        match_other = parser.OFPMatch(eth_type=0x0800, ipv4_dst='10.0.0.2')
        actions_other = [parser.OFPActionOutput(2)]
        self.add_flow(datapath, 1, match_other, actions_other)

        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst='10.0.0.3')
        actions = [parser.OFPActionOutput(3)]
        self.add_flow(datapath, 1, match, actions)
    def setup_sa_flows(self, datapath):
        parser = datapath.ofproto_parser
        # 向 h1 和 h2 同时转发流量
        match = parser.OFPMatch(ipv4_dst='10.0.0.1', eth_type=0x0800)
        actions = [parser.OFPActionOutput(self.h1_port)]
        self.add_flow(datapath, 1, match, actions)

        match = parser.OFPMatch(ipv4_dst='10.0.0.2', eth_type=0x0800)
        actions = [parser.OFPActionOutput(self.h2_port)]
        self.add_flow(datapath, 1, match, actions)


        match_other = parser.OFPMatch(ipv4_dst='10.0.0.3', eth_type=0x0800)
        actions_other = [parser.OFPActionOutput(4)]
        self.add_flow(datapath, 1, match_other, actions_other)

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

            #if self.total_packet_count == 0:
                #video_ratio = 0
            #else:
                #video_ratio = self.video_packet_count / self.total_packet_count

            #self.logger.info(f"Video ratio: {video_ratio}")
            #self.logger.info(f"Total packet count: {self.total_packet_count}")
            #self.logger.info(f"Video packet count: {self.video_packet_count}")
            #self.logger.info(f"Packet count: {self.packet_count}")  # 打印包计数器
            self.logger.info(f"sB packets: {self.sb_packets}")# 打印包计数器
            #self.logger.info(f"sB tx_packets: {self.sb_tx_packets}")
            self.logger.info(f"sC packets: {self.sc_packets}")
            #self.logger.info(f"sC tx_packets: {self.sc_tx_packets}")

            if self.sD_dpid in self.datapaths:
                datapath = self.datapaths[self.sD_dpid]
                self.update_sd_flows(datapath)

            self.video_packet_count = 0
            self.total_packet_count = 0
            self.packet_count = 0  # 重置包计数器

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath_id = ev.msg.datapath.id
        #for stat in body:
            #if datapath_id == int(self.sB_dpid.replace(':', ''), 16):
                #self.sb_rx_packets += stat.rx_packets
                #.sb_tx_packets += stat.tx_packets
            #if datapath_id == int(self.sC_dpid.replace(':', ''), 16):
                #self.sc_rx_packets += stat.rx_packets
                #self.sc_tx_packets += stat.tx_packets
        if datapath_id == int(self.sB_dpid.replace(':', ''), 16):
            for stat in body:
                if stat.port_no == self.sb_target_port:
                    self.sb_packets += stat.tx_packets

        if datapath_id == int(self.sC_dpid.replace(':', ''), 16):
            for stat in body:
                if stat.port_no == self.sc_target_port:
                    self.sc_packets += stat.tx_packets

        # stat in body:
            #if stat.port_no == self.h1_port:
                #self.h1_traffic = stat.tx_bytes
            #elif stat.port_no == self.h2_port:
                #self.h2_traffic = stat.tx_bytes

        # 根据流量动态调整带宽
        #if self.h1_traffic > self.h2_traffic:
            #self.h1_bandwidth = 20
            #self.h2_bandwidth = 10
        #else:
            #self.h1_bandwidth = 10
            #self.h2_bandwidth = 20

        #os.system(f'sudo tc class change dev sA-eth1 parent 1:1 classid 1:10 htb rate {self.h1_bandwidth}mbit')
        #os.system(f'sudo tc class change dev sA-eth2 parent 1:1 classid 1:20 htb rate {self.h2_bandwidth}mbit')

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == CONFIG_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocols(ipv4.ipv4)[0]
            self.total_packet_count += 1
            self.packet_count += 1  # 增加包计数

            # 检查IP包的TTL，防止环路造成的无限循环
            #if ip.ttl <= 1:
                #self.logger.warning("Dropping packet with TTL <= 1 to prevent loop")
                #return

            if ip.proto == 6:
                tcp_pkt = pkt.get_protocols(tcp.tcp)[0]
                if self.is_video_packet(tcp_pkt):
                    self.video_packet_count += 1
            elif ip.proto == 17:
                udp_pkt = pkt.get_protocols(udp.udp)[0]
                if self.is_video_packet(udp_pkt):
                    self.video_packet_count += 1

        #self.logger.info(f"Packet in {datapath.id} in_port {in_port}")
        #actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]
        #out = datapath.ofproto_parser.OFPPacketOut(
            #datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            #actions=actions, data=msg.data)
        #datapath.send_msg(out)

    def is_video_packet(self, pkt):
        video_ports = {80, 443}
        if isinstance(pkt, tcp.tcp) or isinstance(pkt, udp.udp):
            return pkt.src_port in video_ports or pkt.dst_port in video_ports
        return False
