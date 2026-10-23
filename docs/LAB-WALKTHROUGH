# Suricata IDS Lab — Technical Walkthrough

## 1. Lab Objective

Deploy and configure Suricata IDS in an isolated virtual network to detect ICMP Echo Requests, TCP connection attempts, and potentially suspicious bursts of TCP SYN packets.

## 2. Lab Environment

| Component | Configuration |
|---|---|
| Hypervisor | VMware Fusion |
| Operating system | Ubuntu Server 24.04 LTS |
| IDS | Suricata 7.0.3 |
| Scanning tool | Nmap 7.94SVN |
| Network | Host-only, `172.16.60.0/24` |
| Monitored server | `172.16.60.128` |
| Test client | `172.16.60.129` |

Two Ubuntu virtual machines were configured to communicate over the host-only network. The test client also had a separate NAT interface for internet connectivity.

## 3. Network Configuration and Connectivity

Network interfaces were verified on both machines:

```bash
ip -br addr
```

The server used `172.16.60.128/24` and the test client used `172.16.60.129/24`.

Connectivity was tested from the client:

```bash
ping -c 4 172.16.60.128
```

Result: Four packets transmitted, four received, and 0% packet loss.

![Network connectivity and Nmap results](../screenshots/02-network-connectivity-nmap.png)

## 4. Suricata Configuration

Suricata was installed and configured on the monitored Ubuntu server.

The main configuration file was:

```text
/etc/suricata/suricata.yaml
```

Custom signatures were loaded from:

```text
/var/lib/suricata/rules/local.rules
```

The configuration was validated using:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

After successful validation, the service was restarted and its status verified:

```bash
sudo systemctl restart suricata
sudo systemctl status suricata
```

Result: Suricata was `active (running)`.

![Suricata configuration and service status](../screenshots/01-suricata-configuration.png)

## 5. Custom Detection Rules

Three custom signatures were implemented. The complete configuration is available in [`rules/local.rules`](../rules/local.rules).

### Rule 1 — ICMP Echo Request Detection

```text
alert icmp any any -> any any (msg:"ICMP Ping Detected"; itype:8; sid:1000001; rev:1;)
```

Detects ICMP Type 8 packets, commonly generated when a host sends a ping request.

### Rule 2 — TCP Connection Attempt Detection

```text
alert tcp any any -> 172.16.60.128 any (msg:"TCP Connection Attempt Detected"; flags:S; sid:1000002; rev:1;)
```

Detects TCP packets with the SYN flag set, indicating an attempt to initiate a TCP connection to the monitored server.

### Rule 3 — Possible TCP Port Scan Detection

```text
alert tcp any any -> 172.16.60.128 any (msg:"Possible TCP Port Scan"; flags:S; threshold:type both, track by_src, count 20, seconds 10; sid:1000003; rev:1;)
```

Tracks matching TCP SYN packets by source IP address and generates a threshold-based alert when 20 matching packets occur within 10 seconds, while limiting repeated alerts during the window.

This is a possible reconnaissance indicator, not proof of malicious activity. The rule counts matching packets rather than unique destination ports.

## 6. Traffic Generation and Testing

### ICMP Test

On the test client:

```bash
ping -c 4 172.16.60.128
```

Four Echo Requests were sent. Suricata generated corresponding `ICMP Ping Detected` alerts.

### TCP Port Scan Test

On the test client:

```bash
nmap -sT -Pn -p 1-1000 172.16.60.128
```

Nmap results:

- One host scanned and reachable
- Port `22/tcp` open (SSH)
- 999 TCP ports closed

The scan generated TCP SYN traffic, triggering both the TCP connection detection and possible port-scan signatures.

## 7. Alert Verification

Suricata alerts were inspected in:

```text
/var/log/suricata/fast.log
```

Commands used:

```bash
sudo grep 'ICMP Ping Detected' /var/log/suricata/fast.log | tail -n 4
```

```bash
sudo grep 'TCP Connection Attempt Detected' /var/log/suricata/fast.log | tail -n 5
```

```bash
sudo grep 'Possible TCP Port Scan' /var/log/suricata/fast.log | tail -n 5
```

The logs confirmed successful detection using signature IDs `1000001`, `1000002`, and `1000003`.

![Suricata detection alerts](../screenshots/03-suricata-detection-alerts.png)

## 8. Alert Tuning

The initial possible port-scan rule used:

```text
threshold:type threshold, track by_src, count 20, seconds 10;
```

This produced multiple alerts during a single Nmap scan.

The rule was updated to:

```text
threshold:type both, track by_src, count 20, seconds 10;
```

Following validation and a service restart, the subsequent scan produced one visible new port-scan alert, demonstrating reduced alert volume.

## 9. Troubleshooting

Several issues were encountered during implementation:

Virtual network connectivity: The virtual machines required appropriate host-only networking and interface configuration to communicate. The test client also used a NAT interface for external connectivity.

Duplicate rules files: Two copies of `local.rules` existed under `/etc/suricata/rules/` and `/var/lib/suricata/rules/`. Editing the inactive copy caused configuration changes not to appear during validation. The active rules file was identified and the redundant copy removed.

Rule syntax errors: Suricata configuration validation identified invalid rule syntax, including the incorrect `flag` keyword. Correcting it to `flags` allowed the configuration to load successfully.

Historical alerts: The `fast.log` file retained earlier alert messages after detection rules were changed. Fresh traffic and timestamps were used to verify the currently active signatures.

## 10. Results and Lessons Learned

The lab successfully demonstrated:

- Virtual network configuration and connectivity testing
- TCP port and service discovery using Nmap
- Suricata IDS configuration and signature validation
- Custom ICMP and TCP packet detection
- Threshold-based identification of possible reconnaissance activity
- Security log analysis and alert tuning
- Troubleshooting Linux networking and IDS configuration issues

### Limitations

This was a controlled, isolated lab. The port-scan signature detects rapid TCP SYN activity and may also match legitimate traffic. It does not conclusively identify malicious intent, distinguish unique destination ports, or automatically block connections.

## Conclusion

A functional Suricata intrusion detection environment was deployed and validated using controlled ICMP and TCP traffic. The project demonstrates foundational network security monitoring, signature-based detection, and alert analysis.
