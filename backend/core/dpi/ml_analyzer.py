"""
ML-Based DPI Packet Analyzer
Phase 4 Implementation

Features:
- ML-based packet classification using HuggingFace Transformers
- Flow-based feature extraction and statistics
- Async batch processing with background workers
- Threat intelligence and result caching
- JSONL logging for all inferences

Adapted from external DPI module for Phantom-shroud integration.
Uses BERT/DistilBERT for real-time threat detection.

Note: Requires transformers and torch packages.
Optional: GPU acceleration with CUDA.
"""

import os
import json
import time
import logging
from datetime import datetime
from collections import defaultdict
from queue import Queue
from threading import Thread, Lock
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

# Optional ML imports - graceful degradation
try:
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logger.warning("ML packages not available. Install: pip install torch transformers")


# ============================================================================
# FLOW TRACKING FOR ML FEATURES
# ============================================================================

class MLFlowTracker:
    """
    Advanced flow tracker for ML-based feature extraction
    
    Tracks bidirectional flows with forward/backward statistics
    """
    
    def __init__(self, max_age: int = 120):
        """
        Initialize ML Flow Tracker
        
        Args:
            max_age: Maximum age of flows in seconds before cleanup
        """
        self.flows: Dict[str, Dict] = {}
        self.max_age = max_age
        self.lock = Lock()
        
    def get_flow_key(self, parsed_packet: Dict, direction: str = "forward") -> str:
        """
        Generate bidirectional flow key from parsed packet
        
        Args:
            parsed_packet: Parsed packet dictionary
            direction: "forward" or "backward"
            
        Returns:
            Flow key string
        """
        try:
            if 'ip' not in parsed_packet:
                return None
            
            src_ip = parsed_packet['ip']['src']
            dst_ip = parsed_packet['ip']['dst']
            
            # Get ports
            if 'tcp' in parsed_packet:
                src_port = parsed_packet['tcp']['sport']
                dst_port = parsed_packet['tcp']['dport']
            elif 'udp' in parsed_packet:
                src_port = parsed_packet['udp']['sport']
                dst_port = parsed_packet['udp']['dport']
            else:
                src_port = 0
                dst_port = 0
            
            if direction == "forward":
                return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            else:
                return f"{dst_ip}:{dst_port}->{src_ip}:{src_port}"
        except Exception as e:
            logger.debug(f"Error generating flow key: {e}")
            return None
    
    def update_flow(self, parsed_packet: Dict) -> Optional[str]:
        """
        Update flow statistics with new packet
        
        Args:
            parsed_packet: Parsed packet dictionary
            
        Returns:
            Flow key or None
        """
        try:
            forward_key = self.get_flow_key(parsed_packet, "forward")
            backward_key = self.get_flow_key(parsed_packet, "backward")
            
            if not forward_key:
                return None
            
            current_time = time.time()
            packet_size = parsed_packet.get('length', 0)
            
            with self.lock:
                # Check if this is forward or backward direction
                if forward_key in self.flows:
                    flow = self.flows[forward_key]
                    flow["forward_count"] += 1
                    flow_key = forward_key
                elif backward_key in self.flows:
                    flow = self.flows[backward_key]
                    flow["backward_count"] += 1
                    flow_key = backward_key
                else:
                    # New flow
                    flow = {
                        "packets": [],
                        "forward_count": 1,
                        "backward_count": 0,
                        "total_bytes": 0,
                        "start_time": current_time,
                        "last_update": current_time
                    }
                    self.flows[forward_key] = flow
                    flow_key = forward_key
                
                # Update flow
                flow["packets"].append(current_time)
                flow["total_bytes"] += packet_size
                flow["last_update"] = current_time
                
                # Keep only recent packet timestamps (last 100)
                if len(flow["packets"]) > 100:
                    flow["packets"] = flow["packets"][-100:]
            
            return flow_key
            
        except Exception as e:
            logger.debug(f"Error updating flow: {e}")
            return None
    
    def get_flow_stats(self, flow_key: str) -> Tuple[int, int, int]:
        """
        Calculate flow statistics
        
        Args:
            flow_key: Flow identifier
            
        Returns:
            Tuple of (forward_pps, backward_pps, bytes_ps)
        """
        try:
            with self.lock:
                if flow_key not in self.flows:
                    return (0, 0, 0)
                
                flow = self.flows[flow_key]
                if not flow["start_time"]:
                    return (0, 0, 0)
                
                duration = max(0.1, time.time() - flow["start_time"])  # Avoid div/0
                forward_pps = int(flow["forward_count"] / duration)
                backward_pps = int(flow["backward_count"] / duration)
                bytes_ps = int(flow["total_bytes"] / duration)
                
                return (forward_pps, backward_pps, bytes_ps)
        except Exception as e:
            logger.debug(f"Error calculating flow stats: {e}")
            return (0, 0, 0)
    
    def cleanup_old_flows(self):
        """Remove flows older than max_age"""
        try:
            current_time = time.time()
            with self.lock:
                to_remove = [
                    key for key, flow in self.flows.items()
                    if current_time - flow["last_update"] > self.max_age
                ]
                for key in to_remove:
                    del self.flows[key]
                
                if to_remove:
                    logger.debug(f"Cleaned up {len(to_remove)} expired flows")
        except Exception as e:
            logger.error(f"Flow cleanup error: {e}")
    
    def get_active_flow_count(self) -> int:
        """Get number of active flows"""
        with self.lock:
            return len(self.flows)


# ============================================================================
# ML PACKET ANALYZER
# ============================================================================

class MLPacketAnalyzer:
    """
    ML-based packet analyzer using HuggingFace Transformers
    
    Features:
    - BERT/DistilBERT for packet classification
    - Flow-based feature extraction
    - Batch inference for efficiency
    - Threat intelligence with result caching
    - Background worker threads
    """
    
    def __init__(
        self,
        model_path: str = "distilbert-base-uncased-finetuned-sst-2-english",
        batch_size: int = 16,
        log_dir: str = "logs",
        confidence_threshold: float = 0.85
    ):
        """
        Initialize ML Packet Analyzer
        
        Args:
            model_path: HuggingFace model path or identifier
            batch_size: Number of packets to process in batch
            log_dir: Directory for inference logs
            confidence_threshold: Minimum confidence for blocking
        """
        self.model_path = model_path
        self.batch_size = batch_size
        self.confidence_threshold = confidence_threshold
        
        # Check ML availability
        if not ML_AVAILABLE:
            logger.error("ML packages not available. Analyzer will run in dummy mode.")
            self.enabled = False
            return
        
        self.enabled = True
        
        # Setup logging
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.bert_log = self.log_dir / "ml_inference.jsonl"
        
        # Initialize log file
        try:
            with open(self.bert_log, "a", encoding="utf-8") as f:
                pass
            logger.info(f"ML inference log: {self.bert_log}")
        except Exception as e:
            logger.warning(f"Could not initialize ML log: {e}")
        
        # Load model and tokenizer
        logger.info(f"Loading ML model: {model_path}")
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_path)
            self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
            self.model.eval()
            
            # Setup device
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self.model.to(self.device)
            logger.info(f"ML model loaded on {self.device}")
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            self.enabled = False
            return
        
        # Flow tracking
        self.flow_tracker = MLFlowTracker(max_age=120)
        
        # Queues for async processing
        self.packet_queue: Queue = Queue(maxsize=1000)
        self.result_cache: Dict[str, Dict] = {}
        self.cache_lock = Lock()
        
        # Statistics
        self.stats = {
            "total_packets": 0,
            "analyzed_packets": 0,
            "dropped_packets": 0,
            "threats_detected": 0,
            "queue_overflows": 0,
            "false_positives_filtered": 0,
            "cache_hits": 0,
        }
        self.stats_lock = Lock()
        
        # Threat categories to block
        self.block_categories: Set[str] = {
            "Backdoor",
            "Bot",
            "DDoS",
            "DoS",
            "Exploits",
            "Shellcode",
            "Infiltration",
            "Web Attack - SQL Injection",
            "Web Attack - XSS",
            "Web Attack - Brute Force",
        }
        
        # Known safe traffic patterns (whitelist)
        self.safe_patterns: Set[Tuple[str, int]] = {
            ("udp", 53),    # DNS
            ("udp", 5353),  # mDNS
            ("udp", 5355),  # LLMNR
        }
        
        # Start background threads
        self.running = True
        self.analysis_thread = Thread(target=self._analyze_worker, daemon=True)
        self.analysis_thread.start()
        
        self.cleanup_thread = Thread(target=self._cleanup_worker, daemon=True)
        self.cleanup_thread.start()
        
        logger.info("MLPacketAnalyzer initialized successfully")
    
    def _packet_to_model_format(self, parsed_packet: Dict, flow_key: str) -> Optional[str]:
        """
        Convert parsed packet to space-separated string for model input
        
        Args:
            parsed_packet: Parsed packet dictionary
            flow_key: Flow identifier
            
        Returns:
            Feature string or None
        """
        try:
            # Flow statistics
            forward_pps, backward_pps, bytes_ps = self.flow_tracker.get_flow_stats(flow_key)
            
            # Extract packet fields
            src_port = 0
            dst_port = 0
            ip_len = parsed_packet.get('length', 0)
            
            if 'tcp' in parsed_packet:
                src_port = parsed_packet['tcp'].get('sport', 0)
                dst_port = parsed_packet['tcp'].get('dport', 0)
            elif 'udp' in parsed_packet:
                src_port = parsed_packet['udp'].get('sport', 0)
                dst_port = parsed_packet['udp'].get('dport', 0)
            
            # IP features
            ip_ttl = 0
            ip_tos = 0
            if 'ip' in parsed_packet:
                ip_ttl = parsed_packet['ip'].get('ttl', 0)
                ip_tos = parsed_packet['ip'].get('tos', 0)
            
            # TCP flags
            tcp_flags = 0
            if 'tcp' in parsed_packet:
                flags = parsed_packet['tcp'].get('flags', [])
                if 'S' in flags:
                    tcp_flags |= 0x02  # SYN
                if 'A' in flags:
                    tcp_flags |= 0x10  # ACK
                if 'F' in flags:
                    tcp_flags |= 0x01  # FIN
                if 'R' in flags:
                    tcp_flags |= 0x04  # RST
                if 'P' in flags:
                    tcp_flags |= 0x08  # PSH
            
            # Build feature string
            features = [
                str(forward_pps),
                str(backward_pps),
                str(bytes_ps),
                str(src_port),
                str(dst_port),
                str(ip_len),
                str(ip_ttl),
                str(ip_tos),
                str(tcp_flags),
            ]
            
            return " ".join(features)
            
        except Exception as e:
            logger.debug(f"Error converting packet to model format: {e}")
            return None
    
    def _is_likely_safe_traffic(self, parsed_packet: Dict) -> bool:
        """
        Check if traffic matches known safe patterns
        
        Args:
            parsed_packet: Parsed packet dictionary
            
        Returns:
            True if likely safe
        """
        try:
            protocol = "other"
            dst_port = 0
            
            if 'tcp' in parsed_packet:
                protocol = "tcp"
                dst_port = parsed_packet['tcp'].get('dport', 0)
            elif 'udp' in parsed_packet:
                protocol = "udp"
                dst_port = parsed_packet['udp'].get('dport', 0)
            
            # Only whitelist DNS/mDNS - let ML analyze everything else
            return (protocol, dst_port) in self.safe_patterns
            
        except Exception as e:
            logger.debug(f"Error checking safe traffic: {e}")
            return False
    
    def _log_jsonl(self, obj: Dict):
        """Log inference result to JSONL file"""
        try:
            with open(self.bert_log, "a", encoding="utf-8") as f:
                f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.debug(f"ML log write error: {e}")
    
    def _analyze_worker(self):
        """Background worker for ML analysis"""
        batch = []
        
        while self.running:
            try:
                # Collect batch
                while len(batch) < self.batch_size and not self.packet_queue.empty():
                    batch.append(self.packet_queue.get_nowait())
                
                if batch:
                    self._process_batch(batch)
                    batch = []
                else:
                    time.sleep(0.01)  # Small sleep to avoid busy waiting
                    
            except Exception as e:
                logger.error(f"Analysis worker error: {e}")
                batch = []
    
    def _process_batch(self, batch: List[Dict]):
        """
        Process a batch of packets through ML model
        
        Args:
            batch: List of packet dictionaries
        """
        try:
            # Filter valid items
            valid_items = [
                (i, item) for i, item in enumerate(batch)
                if item["text"] is not None
            ]
            
            if not valid_items:
                return
            
            # Extract texts
            texts = [item["text"] for _, item in valid_items]
            
            # Tokenize
            inputs = self.tokenizer(
                texts,
                padding=True,
                truncation=True,
                max_length=256,
                return_tensors="pt"
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            # Inference
            with torch.no_grad():
                outputs = self.model(**inputs)
                predictions = torch.argmax(outputs.logits, dim=-1)
                probabilities = torch.softmax(outputs.logits, dim=-1)
            
            # Process results
            for idx, (i, item) in enumerate(valid_items):
                pred = predictions[idx].item()
                prob = probabilities[idx][pred].item()
                label = self.model.config.id2label.get(pred, str(pred))
                flow_key = item["flow_key"]
                
                # Cache result
                with self.cache_lock:
                    self.result_cache[flow_key] = {
                        "label": label,
                        "confidence": prob,
                        "timestamp": time.time(),
                        "should_block": label in self.block_categories and prob > self.confidence_threshold,
                    }
                
                # Update stats
                with self.stats_lock:
                    self.stats["analyzed_packets"] += 1
                
                # Log inference
                self._log_jsonl({
                    "ts": time.time(),
                    "flow": flow_key[:80],  # Truncate for readability
                    "label": label,
                    "confidence": prob,
                    "text_len": len(item["text"] or ""),
                })
                
                # Check for threats
                if label != "Normal" and prob > self.confidence_threshold and label in self.block_categories:
                    with self.stats_lock:
                        self.stats["threats_detected"] += 1
                    logger.warning(f"Threat detected: {label} ({prob:.2%}) in {flow_key[:50]}")
                
        except Exception as e:
            logger.error(f"Batch processing error: {e}")
    
    def _cleanup_worker(self):
        """Background worker for cleanup tasks"""
        while self.running:
            try:
                time.sleep(30)
                
                # Cleanup old flows
                self.flow_tracker.cleanup_old_flows()
                
                # Cleanup old cache entries
                current_time = time.time()
                with self.cache_lock:
                    to_remove = [
                        k for k, v in self.result_cache.items()
                        if current_time - v["timestamp"] > 120
                    ]
                    for k in to_remove:
                        del self.result_cache[k]
                    
                    if to_remove:
                        logger.debug(f"Cleaned up {len(to_remove)} cached results")
                        
            except Exception as e:
                logger.error(f"Cleanup worker error: {e}")
    
    def should_block_packet(self, parsed_packet: Dict) -> bool:
        """
        Determine if packet should be blocked based on ML analysis
        
        Args:
            parsed_packet: Parsed packet dictionary
            
        Returns:
            True if packet should be blocked
        """
        if not self.enabled:
            return False
        
        try:
            # Update stats
            with self.stats_lock:
                self.stats["total_packets"] += 1
            
            # Check whitelist
            if self._is_likely_safe_traffic(parsed_packet):
                with self.stats_lock:
                    self.stats["false_positives_filtered"] += 1
                return False
            
            # Update flow tracking
            flow_key = self.flow_tracker.update_flow(parsed_packet)
            if not flow_key:
                return False
            
            # Check cache
            with self.cache_lock:
                if flow_key in self.result_cache:
                    result = self.result_cache[flow_key]
                    if time.time() - result["timestamp"] < 60:
                        with self.stats_lock:
                            self.stats["cache_hits"] += 1
                        return result["should_block"]
            
            # Queue for analysis
            if not self.packet_queue.full():
                packet_text = self._packet_to_model_format(parsed_packet, flow_key)
                if packet_text:
                    self.packet_queue.put_nowait({
                        "text": packet_text,
                        "flow_key": flow_key
                    })
            else:
                with self.stats_lock:
                    self.stats["queue_overflows"] += 1
            
            # Don't block immediately - wait for analysis
            return False
            
        except Exception as e:
            logger.debug(f"Error in should_block_packet: {e}")
            return False
    
    def get_stats(self) -> Dict:
        """Get analyzer statistics"""
        with self.stats_lock:
            return {
                **self.stats,
                "queue_size": self.packet_queue.qsize(),
                "cache_size": len(self.result_cache),
                "active_flows": self.flow_tracker.get_active_flow_count(),
                "enabled": self.enabled,
            }
    
    def stop(self):
        """Stop the analyzer and cleanup"""
        logger.info("Stopping MLPacketAnalyzer...")
        self.running = False
        
        if self.enabled:
            self.analysis_thread.join(timeout=5)
            self.cleanup_thread.join(timeout=5)
        
        logger.info("MLPacketAnalyzer stopped")


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    import sys
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("=" * 70)
    print("ML-Based DPI Packet Analyzer - Test Mode")
    print("=" * 70)
    print()
    
    if not ML_AVAILABLE:
        print("❌ ML packages not available!")
        print("Install: pip install torch transformers")
        sys.exit(1)
    
    # Initialize analyzer
    analyzer = MLPacketAnalyzer(
        model_path=os.environ.get("PG_BERT_MODEL", "distilbert-base-uncased-finetuned-sst-2-english"),
        batch_size=8
    )
    
    if not analyzer.enabled:
        print("❌ Analyzer failed to initialize")
        sys.exit(1)
    
    print("[✓] Analyzer initialized")
    print(f"    Model: {analyzer.model_path}")
    print(f"    Device: {analyzer.device}")
    print(f"    Batch size: {analyzer.batch_size}")
    print()
    
    # Simulate some packets
    print("[TEST] Simulating packet analysis...")
    print()
    
    for i in range(10):
        # Create mock parsed packet
        parsed_packet = {
            'timestamp': datetime.now().isoformat(),
            'length': 100 + i * 10,
            'protocols': ['IP', 'TCP'],
            'ip': {
                'src': f'192.0.2.{i % 254 + 1}',
                'dst': f'198.51.100.{(i+1) % 254 + 1}',
                'ttl': 64,
                'tos': 0
            },
            'tcp': {
                'sport': 1000 + i,
                'dport': 80 if i % 2 == 0 else 443,
                'flags': ['S'] if i % 3 == 0 else ['A']
            }
        }
        
        should_block = analyzer.should_block_packet(parsed_packet)
        
        if should_block:
            print(f"🛑 Packet {i}: BLOCKED")
        else:
            print(f"✓ Packet {i}: Allowed")
        
        time.sleep(0.1)
    
    # Wait for analysis
    print("\n[WAIT] Processing batch...")
    time.sleep(3)
    
    # Show statistics
    print("\n[STATISTICS]")
    print("-" * 40)
    stats = analyzer.get_stats()
    for key, value in stats.items():
        print(f"{key}: {value}")
    
    print()
    print("=" * 70)
    print("[✓] Test complete")
    print(f"    Inference log: {analyzer.bert_log}")
    print("=" * 70)
    
    analyzer.stop()
