import pyshark
from typing import List, Dict, Optional, Any
from datetime import datetime
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

                packet_dict = self._process_packet(packet)
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
    
    def clear_buffer(self) -> None:
        """Clear the packet buffer"""
        while not self.packet_buffer.empty():
            try:
                self.packet_buffer.get_nowait()
            except queue.Empty:
                break

    def _process_packet(self, packet) -> Dict[str, Any]:
        """Process a single packet into a standardized dictionary format"""
        try:
            # Base packet information
            packet_dict = {
                'timestamp': safe_float(packet.sniff_timestamp),
                'length': safe_int(packet.length),
                'protocol': safe_str(packet.highest_layer),
                'metadata': {
                    'capture_length': safe_int(packet.captured_length),
                    'interface': safe_str(packet.interface_captured),
                    'frame_info': self._parse_frame_info(packet)
                }
            }

            # Layer processing
            layers = self._process_layers(packet)
            if layers:
                packet_dict.update(layers)

            return packet_dict

        except Exception as e:
            self.logger.error(f"Error processing packet: {str(e)}")
            return {
                'timestamp': datetime.now().timestamp(),
                'length': safe_int(packet.length) if hasattr(packet, 'length') else 0,
                'protocol': 'unknown',
                'error': str(e)
            }

    def _process_layers(self, packet) -> Dict[str, Any]:
        """Process all layers of a packet"""
        layers = {}

        # IP Layer
        if hasattr(packet, 'ip'):
            layers['ip'] = self._parse_ip_layer(packet.ip)

        # TCP Layer
        if hasattr(packet, 'tcp'):
            layers['tcp'] = self._parse_tcp_layer(packet.tcp)

        # UDP Layer
        if hasattr(packet, 'udp'):
            layers['udp'] = self._parse_udp_layer(packet.udp)

        # ICMP Layer
        if hasattr(packet, 'icmp'):
            layers['icmp'] = self._parse_icmp_layer(packet.icmp)

        # DNS Layer
        if hasattr(packet, 'dns'):
            layers['dns'] = self._parse_dns_layer(packet.dns)

        # HTTP Layer
        if hasattr(packet, 'http'):
            layers['http'] = self._parse_http_layer(packet.http)

        # TLS Layer
        if hasattr(packet, 'tls'):
            layers['tls'] = self._parse_tls_layer(packet.tls)

        return layers

    def _parse_frame_info(self, packet) -> Dict[str, Any]:
        """Parse frame information"""
        return {
            'number': safe_int(packet.frame_info.number),
            'time_epoch': safe_float(packet.frame_info.time_epoch),
            'time_delta': safe_float(packet.frame_info.time_delta),
            'protocols': tuple(packet.frame_info.protocols.split(':')) if hasattr(packet.frame_info, 'protocols') else ()
        }

    def _parse_ip_layer(self, ip) -> Dict[str, Any]:
        """Parse IP layer"""
        return {
            'version': safe_int(ip.version, 4),
            'src': safe_str(ip.src),
            'dst': safe_str(ip.dst),
            'ttl': safe_int(ip.ttl, 64),
            'len': safe_int(ip.len),
            'id': safe_int(ip.id),
            'flags': safe_str(ip.flags) if hasattr(ip, 'flags') else None,
            'fragment': bool(int(ip.flags_mf)) if hasattr(ip, 'flags_mf') else None,
            'fragment_offset': safe_int(ip.frag_offset)
        }

    def _parse_tcp_layer(self, tcp) -> Dict[str, Any]:
        """Parse TCP layer"""
        tcp_dict = {
            'srcport': safe_int(tcp.srcport),
            'dstport': safe_int(tcp.dstport),
            'seq': safe_int(tcp.seq),
            'ack': safe_int(tcp.ack) if hasattr(tcp, 'ack') else None,
            'len': safe_int(tcp.len),
            'window_size': safe_int(tcp.window_size),
            'flags': self._parse_tcp_flags(tcp)
        }

        if hasattr(tcp, 'options'):
            tcp_dict['options'] = self._parse_tcp_options(tcp)

        return tcp_dict

    def _parse_tcp_flags(self, tcp) -> Dict[str, bool]:
        """Parse TCP flags"""
        return {
            'SYN': bool(int(getattr(tcp, 'flags_syn', 0))),
            'ACK': bool(int(getattr(tcp, 'flags_ack', 0))),
            'FIN': bool(int(getattr(tcp, 'flags_fin', 0))),
            'RST': bool(int(getattr(tcp, 'flags_reset', 0))),
            'PSH': bool(int(getattr(tcp, 'flags_push', 0))),
            'URG': bool(int(getattr(tcp, 'flags_urg', 0))),
            'ECE': bool(int(getattr(tcp, 'flags_ecn', 0))) if hasattr(tcp, 'flags_ecn') else None,
            'CWR': bool(int(getattr(tcp, 'flags_cwr', 0))) if hasattr(tcp, 'flags_cwr') else None
        }

    def _parse_tcp_options(self, tcp) -> Dict[str, Any]:
        """Parse TCP options"""
        options = {}
        if hasattr(tcp, 'options_mss'):
            options['mss'] = safe_int(tcp.options_mss)
        if hasattr(tcp, 'options_wscale'):
            options['window_scale'] = safe_int(tcp.options_wscale)
        if hasattr(tcp, 'options_sack_perm'):
            options['sack_permitted'] = bool(int(tcp.options_sack_perm))
        return options

    def _parse_udp_layer(self, udp) -> Dict[str, Any]:
        """Parse UDP layer"""
        return {
            'srcport': safe_int(udp.srcport),
            'dstport': safe_int(udp.dstport),
            'length': safe_int(udp.length),
            'checksum': safe_str(udp.checksum) if hasattr(udp, 'checksum') else None
        }

    def _parse_icmp_layer(self, icmp) -> Dict[str, Any]:
        """Parse ICMP layer"""
        return {
            'type': safe_int(icmp.type),
            'code': safe_int(icmp.code),
            'checksum': safe_str(icmp.checksum),
            'sequence_number': safe_int(icmp.seq) if hasattr(icmp, 'seq') else None
        }

    def _parse_dns_layer(self, dns) -> Dict[str, Any]:
        """Parse DNS layer"""
        dns_dict = {
            'type': 'query' if hasattr(dns, 'qry_name') else 'response',
            'id': safe_int(dns.id),
            'flags': {}
        }

        if hasattr(dns, 'qry_name'):
            dns_dict['query'] = {
                'name': safe_str(dns.qry_name),
                'type': safe_str(dns.qry_type)
            }

        if hasattr(dns, 'resp_name'):
            dns_dict['response'] = {
                'name': safe_str(dns.resp_name),
                'type': safe_str(dns.resp_type),
                'ttl': safe_int(dns.resp_ttl) if hasattr(dns, 'resp_ttl') else None
            }

        return dns_dict

    def _parse_http_layer(self, http) -> Dict[str, Any]:
        """Parse HTTP layer"""
        http_dict = {'type': 'request' if hasattr(http, 'request') else 'response'}
        
        if hasattr(http, 'request'):
            http_dict.update({
                'method': safe_str(http.request_method),
                'uri': safe_str(http.request_uri),
                'version': safe_str(http.request_version)
            })
        
        if hasattr(http, 'response'):
            http_dict.update({
                'code': safe_int(http.response_code),
                'phrase': safe_str(http.response_phrase)
            })

        return http_dict

    def _parse_tls_layer(self, tls) -> Dict[str, Any]:
        """Parse TLS layer"""
        return {
            'type': safe_str(tls.record_content_type) if hasattr(tls, 'record_content_type') else None,
            'version': safe_str(tls.record_version) if hasattr(tls, 'record_version') else None,
            'handshake_type': safe_str(tls.handshake_type) if hasattr(tls, 'handshake_type') else None
        }