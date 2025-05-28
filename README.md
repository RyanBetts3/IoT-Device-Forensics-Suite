# IoT-Device-Forensics-Suite

Usage Examples
# Discover IoT devices on network
python iot_forensics.py discover -n 192.168.1.0/24

# Analyze firmware file
python iot_forensics.py firmware suspicious_firmware.bin

# Capture network traffic
python iot_forensics.py capture -t 300 -i eth0

# Extract device configuration
python iot_forensics.py extract 192.168.1.100 -m telnet

# Generate forensic report
python iot_forensics.py report

# Export evidence package
python iot_forensics.py export "Case_2024_001"