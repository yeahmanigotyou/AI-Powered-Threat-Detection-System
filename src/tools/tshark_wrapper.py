import pyshark
from typing import List, Dict, Optional, Any
import queue
from src.monitor.utils.utils import setup_logger, safe_float, safe_int, safe_str

"""
TO DO:
-Code processing of packets in real time
-Save packets in a database for AI/ML training
-Add filtering options
"""

class TsharkWrapper:
    def __init__(self, buffer_size: int = 100000):
        self.logger = setup_logger("TsharkWrapper")
        self.packet_buffer = queue.Queue(maxsize=buffer_size)
        self.stop_flag = False
        self.capture = None
        
    def start_capture(self, interface: str, packet_count: Optional[int] = None) -> None:
        """Start packet capture (runs synchronously, blocking execution)"""
        self.stop_flag = False
        packets_processed = 0
        try:
            self.capture = pyshark.LiveCapture(
                interface=interface,
                include_raw=True,
                use_json=True
            )
            self.logger.info(f"Started capture on interface {interface}")

            for packet in self.capture.sniff_continuously(packet_count=10):
                if self.stop_flag:
                    break

                packet_dict = self._convert_packet_to_dict_(packet)
                try:
                    self.packet_buffer.put_nowait(packet_dict)
                except queue.Full:
                    self.logger.warning("Packet buffer is full, dropping packet")

                packets_processed += 1
                if packet_count and packets_processed >= packet_count:
                    break

        except Exception as e:
            self.logger.error(f"Capture failed: {str(e)}")
        finally:
            self._stop_capture()
            self.logger.info(f"Capture stopped after processing {packets_processed} packets")
            
    def stop_capture(self) -> None:
        """Stop packet capture gracefully"""
        self.logger.info("Stopping capture...")
        self.stop_flag = True
        self._stop_capture()

    def _stop_capture(self):
        """Internal method to clean up capture"""
        if self.capture:
            try:
                self.capture.close()
            except Exception as e:
                self.logger.error(f'Error closing capture: {str(e)}')

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
            # Base packet information with safe conversions
            packet_dict = {
                'timestamp': safe_float(packet.sniff_timestamp),
                'length': safe_int(packet.length),
                'capture_length': safe_int(packet.captured_length),
                'protocol': safe_str(packet.highest_layer),
                'layers': list(packet.layers),
                'interface_captured': safe_str(packet.interface_captured),
                'frame_info': {
                    'number': safe_int(packet.frame_info.number),
                    'time_epoch': safe_float(packet.frame_info.time_epoch),
                    'time_delta': safe_float(packet.frame_info.time_delta),
                    'protocols': packet.frame_info.protocols.split(':') if packet.frame_info.protocols else []
                }
            }

            # IP Layer with safe conversion
            if hasattr(packet, 'ip'):
                packet_dict['ip'] = {
                    'version': safe_int(packet.ip.version, 4),
                    'src': safe_str(packet.ip.src),
                    'dst': safe_str(packet.ip.dst),
                    'ttl': safe_int(packet.ip.ttl, 64),
                    'ds': packet.ip.ds if hasattr(packet.ip, 'ds') else None,
                    'len': safe_int(packet.ip.len),
                    'id': safe_int(packet.ip.id),
                    'flags': packet.ip.flags if hasattr(packet.ip, 'flags') else None,
                    'fragment': bool(int(packet.ip.flags_mf)) if hasattr(packet.ip, 'flags_mf') else None,
                    'fragment_offset': safe_int(packet.ip.frag_offset)
                }

            # TCP Layer
            if hasattr(packet, 'tcp'):
                packet_dict['tcp'] = {
                    'srcport': safe_int(packet.tcp.srcport),
                    'dstport': safe_int(packet.tcp.dstport),
                    'seq': safe_int(packet.tcp.seq),
                    'ack': safe_int(packet.tcp.ack) if hasattr(packet.tcp, 'ack') else None,
                    'len': safe_int(packet.tcp.len),
                    'window_size': safe_int(packet.tcp.window_size),
                    'flags': {
                        'SYN': bool(int(getattr(packet.tcp, 'flags_syn', 0))),
                        'ACK': bool(int(getattr(packet.tcp, 'flags_ack', 0))),
                        'FIN': bool(int(getattr(packet.tcp, 'flags_fin', 0))),
                        'RST': bool(int(getattr(packet.tcp, 'flags_reset', 0))),
                        'PSH': bool(int(getattr(packet.tcp, 'flags_push', 0))),
                        'URG': bool(int(getattr(packet.tcp, 'flags_urg', 0))),
                        'ECE': bool(int(getattr(packet.tcp, 'flags_ecn', 0))) if hasattr(packet.tcp, 'flags_ecn') else None,
                        'CWR': bool(int(getattr(packet.tcp, 'flags_cwr', 0))) if hasattr(packet.tcp, 'flags_cwr') else None
                    },
                    'options': self._parse_tcp_options(packet.tcp) if hasattr(packet.tcp, 'options') else None
                }


            # UDP Layer
            elif hasattr(packet, 'udp'):
                packet_dict['udp'] = {
                    'srcport': safe_int(packet.udp.srcport),
                    'dstport': safe_int(packet.udp.dstport),
                    'length': safe_int(packet.udp.length),
                    'checksum': packet.udp.checksum if hasattr(packet.udp, 'checksum') else None
                }

            # ICMP Layer
            elif hasattr(packet, 'icmp'):
                packet_dict['icmp'] = {
                    'type': safe_int(packet.icmp.type),
                    'code': safe_int(packet.icmp.code),
                    'checksum': packet.icmp.checksum,
                    'sequence_number': safe_int(packet.icmp.seq) if hasattr(packet.icmp, 'seq') else None
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
                'timestamp': safe_float(packet.sniff_timestamp),
                'length': safe_int(packet.length),
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