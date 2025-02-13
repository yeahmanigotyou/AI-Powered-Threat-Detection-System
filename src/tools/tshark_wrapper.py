import pyshark
from typing import List, Dict, Optional, Any
import threading
import queue
from src.monitor.utils.utils import setup_logger

"""
TO DO:
-Code processing of packets in real time
-Save packets in a database for AI/ML training
-Add filtering options
"""

class TsharkWrapper:
    def __init__(self, buffer_size: int = 1000):
        self.default_options = ['-T', 'json']
        self.logger = setup_logger("TsharkWrapper")
        self.packet_buffer = queue.Queue(maxsize=buffer_size)
        self.stop_capture = threading.Event()
        self.capture_thread = None
        self.processing_thread = None

    def start_capture(self, interface: str, packet_count: Optional[int] = None) -> None:
        """Start packet capture in a separate thread"""
        self.stop_capture.clear()
        self.capture_thread = threading.Thread(
            target=self._capture_packets_async,
            args=(interface, packet_count)
        )
        self.capture_thread.start()

    def stop_capture(self) -> None:
        """Stop the packet capture gracefully"""
        self.stop_capture.set()
        if self.capture_thread:
            self.capture_thread.join()

    def _capture_packets_async(self, interface: str, packet_count: Optional[int] = None) -> None:
        try:
            capture = pyshark.LiveCapture(
                interface=interface,
                include_raw=True,
                use_json=True,
                custom_parameters={
                    '-n': '',  # Don't resolve names
                    '-C': '100',  # Packet buffer size
                    '-s': '0'  # Snapshot length (0 = unlimited)
                }
            )
            
            packets_processed = 0
            for packet in capture.sniff_continuously():
                if self.stop_capture.is_set():
                    break
                    
                packet_dict = self._convert_packet_to_dict_(packet)
                self.packet_buffer.put(packet_dict)
                
                packets_processed += 1
                if packet_count and packets_processed >= packet_count:
                    break
                    
        except Exception as e:
            self.logger.error(f"Capture failed: {str(e)}")
            raise

    def get_packets(self, batch_size: int = 100) -> List[Dict]:
        """Retrieve packets from the buffer"""
        packets = []
        try:
            while len(packets) < batch_size and not self.packet_buffer.empty():
                packets.append(self.packet_buffer.get_nowait())
        except queue.Empty:
            pass
        return packets

    def _convert_packet_to_dict_(self, packet) -> Dict[str, Any]:
        try:
            # Base packet information
            packet_dict = {
                'timestamp': float(packet.sniff_timestamp),
                'length': int(packet.length),
                'capture_length': int(packet.captured_length),
                'protocol': packet.highest_layer,
                'layers': list(packet.layers),
                'interface_captured': packet.interface_captured,
                'frame_info': {
                    'number': int(packet.frame_info.number),
                    'time_epoch': float(packet.frame_info.time_epoch),
                    'time_delta': float(packet.frame_info.time_delta),
                    'protocols': packet.frame_info.protocols.split(':')
                }
            }

            # IP Layer
            if hasattr(packet, 'ip'):
                packet_dict['ip'] = {
                    'version': int(packet.ip.version),
                    'src': packet.ip.src,
                    'dst': packet.ip.dst,
                    'ttl': int(packet.ip.ttl),
                    'ds': packet.ip.ds if hasattr(packet.ip, 'ds') else None,
                    'len': int(packet.ip.len),
                    'id': packet.ip.id,
                    'flags': packet.ip.flags if hasattr(packet.ip, 'flags') else None,
                    'fragment': bool(int(packet.ip.flags_mf)) if hasattr(packet.ip, 'flags_mf') else None,
                    'fragment_offset': int(packet.ip.frag_offset) if hasattr(packet.ip, 'frag_offset') else None
                }

            # TCP Layer
            if hasattr(packet, 'tcp'):
                packet_dict['tcp'] = {
                    'srcport': int(packet.tcp.srcport),
                    'dstport': int(packet.tcp.dstport),
                    'seq': int(packet.tcp.seq),
                    'ack': int(packet.tcp.ack) if hasattr(packet.tcp, 'ack') else None,
                    'len': int(packet.tcp.len),
                    'window_size': int(packet.tcp.window_size),
                    'flags': {
                        'SYN': bool(int(packet.tcp.flags_syn)),
                        'ACK': bool(int(packet.tcp.flags_ack)),
                        'FIN': bool(int(packet.tcp.flags_fin)),
                        'RST': bool(int(packet.tcp.flags_reset)),
                        'PSH': bool(int(packet.tcp.flags_push)),
                        'URG': bool(int(packet.tcp.flags_urg)),
                        'ECE': bool(int(packet.tcp.flags_ecn)) if hasattr(packet.tcp, 'flags_ecn') else None,
                        'CWR': bool(int(packet.tcp.flags_cwr)) if hasattr(packet.tcp, 'flags_cwr') else None
                    },
                    'options': self._parse_tcp_options(packet.tcp) if hasattr(packet.tcp, 'options') else None
                }

            # UDP Layer
            elif hasattr(packet, 'udp'):
                packet_dict['udp'] = {
                    'srcport': int(packet.udp.srcport),
                    'dstport': int(packet.udp.dstport),
                    'length': int(packet.udp.length),
                    'checksum': packet.udp.checksum if hasattr(packet.udp, 'checksum') else None
                }

            # ICMP Layer
            elif hasattr(packet, 'icmp'):
                packet_dict['icmp'] = {
                    'type': int(packet.icmp.type),
                    'code': int(packet.icmp.code),
                    'checksum': packet.icmp.checksum,
                    'sequence_number': int(packet.icmp.seq) if hasattr(packet.icmp, 'seq') else None
                }

            # DNS Layer
            if hasattr(packet, 'dns'):
                packet_dict['dns'] = self._parse_dns_layer(packet.dns)

            # HTTP Layer
            if hasattr(packet, 'http'):
                packet_dict['http'] = self._parse_http_layer(packet.http)

            # TLS Layer
            if hasattr(packet, 'tls'):
                packet_dict['tls'] = self._parse_tls_layer(packet.tls)

            return packet_dict

        except Exception as e:
            self.logger.error(f"Error converting packet: {str(e)}")
            # Return minimal packet information on error
            return {
                'timestamp': float(packet.sniff_timestamp),
                'length': int(packet.length),
                'protocol': 'unknown',
                'error': str(e)
            }

    def _parse_tcp_options(self, tcp) -> Dict:
        """Parse TCP options"""
        options = {}
        if hasattr(tcp, 'options_mss'):
            options['mss'] = int(tcp.options_mss)
        if hasattr(tcp, 'options_wscale'):
            options['window_scale'] = int(tcp.options_wscale)
        if hasattr(tcp, 'options_sack_perm'):
            options['sack_permitted'] = bool(int(tcp.options_sack_perm))
        return options

    def _parse_dns_layer(self, dns) -> Dict:
        """Parse DNS layer information"""
        dns_dict = {
            'type': 'query' if hasattr(dns, 'qry_name') else 'response',
            'id': int(dns.id),
            'flags': {}
        }

        if hasattr(dns, 'qry_name'):
            dns_dict['query'] = {
                'name': dns.qry_name,
                'type': dns.qry_type
            }

        if hasattr(dns, 'resp_name'):
            dns_dict['response'] = {
                'name': dns.resp_name,
                'type': dns.resp_type,
                'ttl': int(dns.resp_ttl) if hasattr(dns, 'resp_ttl') else None
            }

        return dns_dict

    def _parse_http_layer(self, http) -> Dict:
        """Parse HTTP layer information"""
        http_dict = {'type': 'request' if hasattr(http, 'request') else 'response'}
        
        if hasattr(http, 'request'):
            http_dict.update({
                'method': http.request_method,
                'uri': http.request_uri,
                'version': http.request_version
            })
        
        if hasattr(http, 'response'):
            http_dict.update({
                'code': int(http.response_code),
                'phrase': http.response_phrase
            })

        return http_dict

    def _parse_tls_layer(self, tls) -> Dict:
        """Parse TLS layer information"""
        tls_dict = {
            'type': tls.record_content_type if hasattr(tls, 'record_content_type') else None,
            'version': tls.record_version if hasattr(tls, 'record_version') else None
        }

        if hasattr(tls, 'handshake_type'):
            tls_dict['handshake_type'] = tls.handshake_type

        return tls_dict