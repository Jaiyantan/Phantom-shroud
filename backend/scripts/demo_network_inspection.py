#!/usr/bin/env python3
"""
Network Inspection System - Phase 1 Demo
Quick demo script to test the network inspection functionality
"""

import sys
import time
import logging
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.network_inspector import NetworkInspector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def main():
    """Main demo function"""
    print("=" * 60)
    print("Network Inspection System - Phase 1 Demo")
    print("=" * 60)
    print()
    
    try:
        # Initialize network inspector
        print("[1/4] Initializing Network Inspector...")
        inspector = NetworkInspector(auto_start=False)
        print(f"✓ Initialized on interface: {inspector.interface}")
        print()
        
        # List available interfaces
        print("[2/4] Available Network Interfaces:")
        interfaces = inspector.get_interfaces()
        for iface in interfaces:
            info = inspector.get_interface_info(iface)
            if info and 'addresses' in info:
                ipv4 = info['addresses'].get('ipv4', 'N/A')
                print(f"  - {iface}: {ipv4}")
        print()
        
        # Start inspection
        print("[3/4] Starting network inspection...")
        print("Note: This requires root/sudo privileges!")
        inspector.start()
        print("✓ Inspection started")
        print()
        
        # Monitor for a short time
        print("[4/4] Monitoring traffic for 10 seconds...")
        print("(You may need to generate some network traffic)")
        print()
        
        for i in range(10):
            time.sleep(1)
            stats = inspector.get_stats()
            
            print(f"\r[{i+1}/10] Packets: {stats['flows']['total_packets']:,} | "
                  f"Flows: {stats['flows']['active_flows']} | "
                  f"PPS: {stats['packets_per_second']:.2f}", end='', flush=True)
        
        print("\n")
        
        # Display final statistics
        print("Final Statistics:")
        print("-" * 60)
        stats = inspector.get_stats()
        print(f"Total Packets:     {stats['flows']['total_packets']:,}")
        print(f"Total Bytes:       {stats['flows']['total_bytes']:,}")
        print(f"Active Flows:      {stats['flows']['active_flows']}")
        print(f"Total Flows:       {stats['flows']['total_flows']}")
        print(f"Packets/Second:    {stats['packets_per_second']:.2f}")
        print()
        
        # Show protocol distribution
        if stats['protocols']:
            print("Protocol Distribution:")
            for protocol, count in stats['protocols'].items():
                print(f"  {protocol:10s}: {count}")
            print()
        
        # Show top flows
        top_flows = inspector.get_top_talkers(limit=5, by='bytes')
        if top_flows:
            print("Top 5 Flows (by bytes):")
            print(f"{'Source IP':<15} {'Dest IP':<15} {'Protocol':<8} {'Packets':<8} {'Bytes'}")
            print("-" * 60)
            for flow in top_flows:
                print(f"{flow['src_ip']:<15} {flow['dst_ip']:<15} "
                      f"{flow['protocol']:<8} {flow['packet_count']:<8} {flow['byte_count']}")
            print()
        
        # Stop inspection
        print("Stopping network inspection...")
        inspector.stop()
        print("✓ Inspection stopped")
        print()
        
        print("=" * 60)
        print("Demo completed successfully!")
        print("=" * 60)
        
    except PermissionError:
        print("\n❌ Error: Permission denied!")
        print("Packet capture requires root privileges.")
        print("Please run with sudo:")
        print(f"  sudo python3 {__file__}")
        sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        if 'inspector' in locals() and inspector.is_running:
            inspector.stop()
        sys.exit(0)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        logger.exception("Demo failed")
        sys.exit(1)


if __name__ == '__main__':
    main()
