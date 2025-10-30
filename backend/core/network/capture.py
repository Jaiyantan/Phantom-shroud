"""
Packet Capture Module
Handles real-time packet capture using Scapy
"""

import logging
import threading
from typing import Optional, Callable, List
from scapy.all import sniff, conf
from queue import Queue, Empty
import time

logger = logging.getLogger(__name__)


class PacketCapture:
    """
    Handles packet capture from network interfaces
    """
    
    def __init__(self, interface: Optional[str] = None, buffer_size: int = 1000):
        """
        Initialize Packet Capture
        
        Args:
            interface: Network interface to capture from (auto-detect if None)
            buffer_size: Size of packet buffer queue
        """
        self.interface = interface
        self.buffer_size = buffer_size
        self.packet_queue = Queue(maxsize=buffer_size)
        self.is_running = False
        self.capture_thread = None
        self.packet_count = 0
        self.dropped_packets = 0
        self._callbacks = []
        self._stop_event = threading.Event()
        
        # Capture filter (BPF syntax)
        self.capture_filter = None
        
        logger.info(f"PacketCapture initialized on interface: {interface or 'default'}")
    
    def set_filter(self, bpf_filter: str):
        """
        Set BPF (Berkeley Packet Filter) for capture
        
        Args:
            bpf_filter: BPF filter string (e.g., "tcp port 80")
        """
        self.capture_filter = bpf_filter
        logger.info(f"Capture filter set: {bpf_filter}")
    
    def register_callback(self, callback: Callable):
        """
        Register a callback function to be called for each packet
        
        Args:
            callback: Function that takes a packet as argument
        """
        if callback not in self._callbacks:
            self._callbacks.append(callback)
            logger.debug(f"Registered callback: {callback.__name__}")
    
    def unregister_callback(self, callback: Callable):
        """
        Unregister a callback function
        
        Args:
            callback: Callback function to remove
        """
        if callback in self._callbacks:
            self._callbacks.remove(callback)
            logger.debug(f"Unregistered callback: {callback.__name__}")
    
    def _packet_handler(self, packet):
        """
        Internal packet handler called by Scapy
        
        Args:
            packet: Scapy packet object
        """
        try:
            self.packet_count += 1
            
            # Try to add to queue
            try:
                self.packet_queue.put_nowait(packet)
            except:
                self.dropped_packets += 1
                logger.debug(f"Packet queue full, dropped packet (total dropped: {self.dropped_packets})")
            
            # Call registered callbacks
            for callback in self._callbacks:
                try:
                    callback(packet)
                except Exception as e:
                    logger.error(f"Error in callback {callback.__name__}: {e}")
                    
        except Exception as e:
            logger.error(f"Error in packet handler: {e}")
    
    def start(self, prn: Optional[Callable] = None, count: int = 0):
        """
        Start packet capture in a background thread
        
        Args:
            prn: Additional packet processing function
            count: Number of packets to capture (0 = infinite)
        """
        if self.is_running:
            logger.warning("Packet capture is already running")
            return
        
        self.is_running = True
        self._stop_event.clear()
        
        # Combine internal handler with user-provided function
        def combined_handler(pkt):
            self._packet_handler(pkt)
            if prn:
                prn(pkt)
        
        # Start capture in background thread
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(combined_handler, count),
            daemon=True
        )
        self.capture_thread.start()
        
        logger.info(f"Packet capture started on {self.interface or 'default interface'}")
    
    def _capture_loop(self, prn: Callable, count: int):
        """
        Main capture loop running in background thread
        
        Args:
            prn: Packet processing function
            count: Number of packets to capture
        """
        try:
            # Configure Scapy to be less verbose
            conf.verb = 0
            
            # Start sniffing
            sniff(
                iface=self.interface,
                prn=prn,
                filter=self.capture_filter,
                count=count,
                store=False,  # Don't store packets in memory
                stop_filter=lambda x: self._stop_event.is_set()
            )
            
        except Exception as e:
            logger.error(f"Error in capture loop: {e}")
        finally:
            self.is_running = False
            logger.info("Packet capture stopped")
    
    def stop(self):
        """Stop packet capture"""
        if not self.is_running:
            logger.warning("Packet capture is not running")
            return
        
        logger.info("Stopping packet capture...")
        self._stop_event.set()
        self.is_running = False
        
        # Wait for capture thread to finish
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
    
    def get_packet(self, timeout: float = 1.0):
        """
        Get a packet from the buffer queue
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            Packet object or None if timeout
        """
        try:
            return self.packet_queue.get(timeout=timeout)
        except Empty:
            return None
    
    def get_packets(self, count: int = 10, timeout: float = 1.0) -> List:
        """
        Get multiple packets from buffer
        
        Args:
            count: Maximum number of packets to retrieve
            timeout: Timeout in seconds for each packet
            
        Returns:
            List of packet objects
        """
        packets = []
        
        for _ in range(count):
            packet = self.get_packet(timeout=timeout)
            if packet is None:
                break
            packets.append(packet)
        
        return packets
    
    def clear_buffer(self):
        """Clear the packet buffer queue"""
        while not self.packet_queue.empty():
            try:
                self.packet_queue.get_nowait()
            except Empty:
                break
        
        logger.debug("Packet buffer cleared")
    
    def get_statistics(self) -> dict:
        """
        Get capture statistics
        
        Returns:
            Dictionary with statistics
        """
        return {
            'is_running': self.is_running,
            'interface': self.interface,
            'packet_count': self.packet_count,
            'dropped_packets': self.dropped_packets,
            'buffer_size': self.buffer_size,
            'buffer_usage': self.packet_queue.qsize(),
            'filter': self.capture_filter
        }
    
    def reset_statistics(self):
        """Reset capture statistics"""
        self.packet_count = 0
        self.dropped_packets = 0
        logger.info("Capture statistics reset")


class PacketCaptureManager:
    """
    Manages multiple packet capture instances
    """
    
    def __init__(self):
        """Initialize Packet Capture Manager"""
        self.captures = {}
        logger.info("PacketCaptureManager initialized")
    
    def create_capture(self, name: str, interface: Optional[str] = None, 
                      buffer_size: int = 1000) -> PacketCapture:
        """
        Create a new packet capture instance
        
        Args:
            name: Unique name for this capture
            interface: Network interface
            buffer_size: Buffer size
            
        Returns:
            PacketCapture instance
        """
        if name in self.captures:
            logger.warning(f"Capture '{name}' already exists")
            return self.captures[name]
        
        capture = PacketCapture(interface=interface, buffer_size=buffer_size)
        self.captures[name] = capture
        
        logger.info(f"Created capture: {name}")
        return capture
    
    def get_capture(self, name: str) -> Optional[PacketCapture]:
        """
        Get a capture instance by name
        
        Args:
            name: Name of the capture
            
        Returns:
            PacketCapture instance or None
        """
        return self.captures.get(name)
    
    def remove_capture(self, name: str):
        """
        Remove and stop a capture instance
        
        Args:
            name: Name of the capture
        """
        if name in self.captures:
            capture = self.captures[name]
            if capture.is_running:
                capture.stop()
            del self.captures[name]
            logger.info(f"Removed capture: {name}")
    
    def stop_all(self):
        """Stop all capture instances"""
        for name, capture in self.captures.items():
            if capture.is_running:
                capture.stop()
        
        logger.info("All captures stopped")
    
    def get_all_statistics(self) -> dict:
        """
        Get statistics for all captures
        
        Returns:
            Dictionary with statistics for each capture
        """
        stats = {}
        for name, capture in self.captures.items():
            stats[name] = capture.get_statistics()
        
        return stats
