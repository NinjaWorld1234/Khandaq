import time
import json
import logging
from typing import Dict, Any

from shared.base_agent import BaseAgent
from shared.wazuh_client import WazuhClient

class HardwareAnomalyAgent(BaseAgent):
    """
    Agent 48: Hardware Anomaly & Physical Breach Monitor
    Monitors for spy chips, covert microcode execution, and physical chassis intrusions.
    """

    def __init__(self):
        super().__init__(
            name="w48_hardware_anomaly",
            description="Detects hardware-level espionage: Thermal/Load discrepancies, unauthorized PCIe/USB devices, and chassis intrusion.",
            interval_seconds=60,
            supervisor_channel="soc:commander" # Direct to Commander due to critical physical threat
        )
        self.wazuh = WazuhClient()
        self.baseline_devices = set()

    def run(self):
        self.logger.info("Polling hardware sensors and PCI/USB telemetry...")
        
        # 1. Thermal vs OS Load Discrepancy (The Spy Chip Detector)
        # If CPU temp is high but OS reports 0% load, a hardware implant or ring-2 malware is executing.
        thermal_alerts = self.wazuh.get_alerts(rule_id="100048") # Custom rule ID for hardware sensors
        
        for alert in thermal_alerts:
            cpu_temp = alert.get("data", {}).get("cpu_temp_c", 0)
            os_load = alert.get("data", {}).get("os_cpu_load_pct", 0)
            
            if cpu_temp > 75 and os_load < 5:
                self.logger.critical(f"THERMAL ANOMALY DETECTED! CPU Temp: {cpu_temp}C, OS Load: {os_load}%")
                self.publish_alert(
                    level="CRITICAL",
                    title="Potential Hardware Spy Chip or Covert Execution",
                    description=f"Massive thermal output ({cpu_temp}C) with zero OS-level utilization ({os_load}%). Hardware-level covert channel suspected.",
                    source="hardware_sensors",
                    raw_data=alert
                )

        # 2. Unauthorized PCIe / USB Device Addition (Rubber Ducky / DMA Attack)
        device_alerts = self.wazuh.get_alerts(rule_id="100049") # Custom rule for udev/PCI additions
        for alert in device_alerts:
            device_id = alert.get("data", {}).get("vendor_product_id")
            device_name = alert.get("data", {}).get("device_name", "Unknown")
            
            if device_id not in self.baseline_devices and self.baseline_devices:
                self.logger.critical(f"UNAUTHORIZED HARDWARE ADDED: {device_name} ({device_id})")
                self.publish_alert(
                    level="CRITICAL",
                    title="Unauthorized Physical Device Connected",
                    description=f"A new hardware device {device_name} was plugged into the server physically.",
                    source="udev_monitor",
                    raw_data=alert
                )
            
            # Update baseline
            if device_id:
                self.baseline_devices.add(device_id)

        # 3. Chassis Intrusion Detection
        intrusion_alerts = self.wazuh.get_alerts(rule_id="100050") # Custom rule for IPMI/BMC chassis intrusion
        for alert in intrusion_alerts:
            status = alert.get("data", {}).get("chassis_status")
            if status == "OPEN":
                self.logger.critical("SERVER CHASSIS OPENED!")
                self.publish_alert(
                    level="CRITICAL",
                    title="Physical Server Breach (Chassis Intrusion)",
                    description="The server's physical case has been opened. Immediate physical security response required.",
                    source="ipmi_bmc",
                    raw_data=alert
                )

if __name__ == "__main__":
    agent = HardwareAnomalyAgent()
    agent.start()
