# Phantom-shroud
# Privacy Guard for Public Wi-Fi Networks

## Phase 1: Passive Detection & Host Hardening (D.S.O.N.E.)

Phase 1 focuses on establishing the initial security baseline. This involves confirming the network environment, hardening the host device's settings to minimize exposure, and alerting the user to potential immediate threats before connecting.

### 1. ⚙️ Host Hardening: Minimize Exposure
The agent's first step is to lock down local device settings, minimizing the attack surface visible to other devices on the public Wi-Fi network.

| Action                         | Description                                                                                                                                      | Rationale                                                                                             |
|--------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| **Disable File/Printer Sharing** | Ensure file and printer sharing services are completely disabled on the network interface being used.                                             | Prevents unauthorized network users from browsing local files or accessing shared resources.       |
| **Firewall Activation**         | Verify that the device's host-based firewall is active and set to a strict profile (e.g., block all unsolicited inbound connections).               | Acts as the primary defense against direct connection attempts and port probing from local network peers. |
| **Disable Auto-Connect**        | Configure the device to "forget" or not auto-connect to public/unknown SSIDs.                                                                     | Prevents the device from automatically joining a spoofed "Evil Twin" network upon entering a location. |
| **Disable Non-Essential Services** | Disable unnecessary protocols and services (e.g., Bluetooth discovery, UPnP) while on public Wi-Fi.                                                | Reduces the number of potential vectors for local exploitation.                                      |

### 2. 🔍 Network Context and Initial Detection
Before any data transmission, the agent analyzes the network environment to assess immediate risk.

| Action                         | Detection Method                                                                                                                                  | Alert                                                                                                      |
|--------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|
| **Network Name Verification (Rogue AP Check)** | Alert if the network name (SSID) is generic (e.g., "Free Wi-Fi") or mimics a known, trusted network (potential "Evil Twin").                      | Alert if SSID seems suspicious or attempts to match a known network name.                                  |
| **Encryption Check**           | Determine if the network is Open (no password/encryption) or uses a modern protocol (WPA2/WPA3).                                                  | Critical alert if the network is Open/Unsecured (no Layer 2 encryption).                                  |
| **DNS Snooping**               | Monitor the configured DNS server. Alert if the DNS server is insecure or configured to a non-standard local IP address, suggesting a potential MITM attack. | Alert if the DNS server is insecure or unusual, indicating a potential Man-In-The-Middle (MITM) attack. |

### 3. 📝 Forensics (Baseline Recording)
Establish the system's baseline configuration before connecting, to serve as a reference point for Stage 2 anomaly detection.

| Data Point                    | Description                                                                                                                                      |
|--------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| **Gateway IP and MAC Address** | Record the initial Gateway IP and MAC Address before connecting to the network.                                                                  |
| **Initial Time-To-Live (TTL)** | Record the device's initial Time-To-Live (TTL) value for outbound packets.                                                                       |
| **Firewall Rules & Sharing Services** | Record the state of all host Firewall Rules and Sharing Services to detect anomalies in future.                                                 |

---

## Next Steps
Phase 2 shifts from passive hardening to active defense against network-level attacks. It focuses on detecting and deceiving Layer 2 MITM attacks (ARP Spoofing) and port probing. The required measures for **Phase 2: ARP / L2 MITM & Port Probing Defense** are detailed in the next section of this documentation.