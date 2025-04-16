import machine
import network
from umqtt.simple import MQTTClient
import json
import dht
import bluetooth
import time
from micropython import const
import hashlib
import binascii
import ubinascii
from cryptolib import aes


# Pin configuration
WHITE_LED = machine.Pin(33, machine.Pin.OUT)
RED_LED = machine.Pin(32, machine.Pin.OUT)
BUTTON = machine.Pin(27, machine.Pin.IN, machine.Pin.PULL_UP)  # Active low button


# DHT sensor and thresholds
DHT = dht.DHT11(machine.Pin(13))
TEMP_THRESHOLD = 30  # Example temperature threshold
HUMIDITY_THRESHOLD = 60  # Example humidity threshold
sleep_time_ms = 3


# WiFi and MQTT configuration
WIFI_SSID = ""
WIFI_PW = ''
CERT_FILE = "...cert.pem"
KEY_FILE = "...private.key"
MQTT_CLIENT_ID = "..."
MQTT_PORT = 8883
MQTT_TOPIC = "..."
MQTT_HOST = "...iot.eu-central-1.amazonaws.com"


mqtt_client = None
is_main = True  # True for main, False for backup
key = b"uLBsUpeRkeY2024x" # Key for RC4, TEA, AES
condition = b"esp_run"
last_received = time.time()
#condition = b"esp_stop"


# Base64 Encoding Function
def base64_encode(data):
    """Encodes the input data using Base64."""
    return ubinascii.b2a_base64(data).strip()


# AES Encryption
def aes_encrypt(data, key):
    """
    Encrypts the data using AES in ECB mode.
    Key must be 16, 24, or 32 bytes long.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes long.")
    
    cipher = aes(key, 1)  # AES.MODE_ECB = 1 in MicroPython
    padding_length = 16 - (len(data) % 16)
    data += bytes([padding_length] * padding_length)  # PKCS#7 padding
    encrypted = cipher.encrypt(data)
    return encrypted


def rc4(key, data):
    s = list(range(256))
    j = 0
    out = []


    # Key-scheduling algorithm (KSA)
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]


    i = j = 0
    # Pseudo-random generation algorithm (PRGA)
    for char in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(char ^ s[(s[i] + s[j]) % 256])


    return bytes(out)


def tea(data, key):
    pad_length = 8 - len(data)
    data += b'\x00' * pad_length 


    v0, v1 = int.from_bytes(data[:4], 'big'), int.from_bytes(data[4:8], 'big')
    k = [int.from_bytes(key[i:i+4], 'big') for i in range(0, 16, 4)]
    delta, sum_ = 0x9E3779B9, 0
    for _ in range(32):  # 32 rounds
        sum_ = (sum_ + delta) & 0xFFFFFFFF
        v0 = (v0 + (((v1 << 4) + k[0]) ^ (v1 + sum_) ^ ((v1 >> 5) + k[1]))) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4) + k[2]) ^ (v0 + sum_) ^ ((v0 >> 5) + k[3]))) & 0xFFFFFFFF
    return (v0.to_bytes(4, 'big') + v1.to_bytes(4, 'big'))


def bytes_to_hex(data):
    return ''.join(f'{byte:02X}' for byte in data)  # Convert bytes to hex string


def rc4_encryption(data, key, name="ULB:"):
    # Encrypt using RC4
    encrypted = rc4(key, data.encode())
    # Convert encrypted text to a hex string
    encrypted_str = bytes_to_hex(encrypted)
    # Add the encrypted text to the advertising name
    # Flags: LE General Discoverable Mode, BR/EDR Not Supported
    payload = b'\x02\x01\x06' + name + encrypted_str
    return payload


def tea_encryption(data, key, name="ULB:"):
    #Encrypt using TEA
    encrypted = tea(data, key)
    # Convert encrypted text to a hex string
    encrypted_str = bytes_to_hex(encrypted)
    # Add the encrypted text to the advertising name
    # Flags: LE General Discoverable Mode, BR/EDR Not Supported
    payload = b'\x02\x01\x06' + name + encrypted_str
    return payload


def bluetooth_sender(bt):
    # Start advertising
    #payload = rc4_encryption(data, key)
    payload = tea_encryption(condition, key)
    bt.gap_advertise(20000, adv_data=payload)
    print(f"Advertising as {payload}...")
    time.sleep(20)
        
def tea_d(encrypted_data, key):
    if len(encrypted_data) != 8:
        raise ValueError("Encrypted data must be exactly 8 bytes")
    
    v0, v1 = int.from_bytes(encrypted_data[:4], 'big'), int.from_bytes(encrypted_data[4:8], 'big')
    k = [int.from_bytes(key[i:i+4], 'big') for i in range(0, 16, 4)]
    delta, sum_ = 0x9E3779B9, 0x9E3779B9 * 32


    for _ in range(32):  # 32 rounds, reversed
        v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + sum_) ^ ((v0 >> 5) + k[3]))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + sum_) ^ ((v1 >> 5) + k[1]))) & 0xFFFFFFFF
        sum_ = (sum_ - delta) & 0xFFFFFFFF


    decrypted = v0.to_bytes(4, 'big') + v1.to_bytes(4, 'big')
    return decrypted


def hex_to_bytes(hex_str):
    # Convert a hex string to bytes manually
    byte_array = bytearray()
    for i in range(0, len(hex_str), 2):
        byte_array.append(int(hex_str[i:i+2], 16))
    return bytes(byte_array)


def bluetooth_receiver(bt):
    # IRQ callback
    def bt_irq(event, data):
        global is_main
        if event == 5:  # SCAN_RESULT event
            addr_type, addr, adv_type, rssi, adv_data = data
            adv_data_bytes = bytes(adv_data)  # Convert memoryview to bytes
            print(f"Device found: RSSI={rssi}, Data={adv_data_bytes}")


            # Check if "ULB" is in the advertising data
            if b"ULB:" in adv_data_bytes:
                print("ESP32_Sender found!")
                # Extract the encrypted data from the advertising data
                name_start = adv_data_bytes.find(b"ULB:") + len("ULB:")
                encrypted_hex = adv_data_bytes[name_start:].decode("utf-8")
                print(f"Encrypted: {encrypted_hex}")


                # Convert hex string back to bytes
                encrypted = hex_to_bytes(encrypted_hex)


                # Decrypt the cipher using RC4
                try:
                    decrypted = tea_d(encrypted, key).decode().replace("\x00", "")
                    print(f"Decrypted: {decrypted}")
                    last_received = time.time()
                    if decrypted == "esp_run":
                        is_main = False
                        print("1")
                    elif decrypted == "esp_stop":
                        is_main = True
                        print("2")
                    else:
                        is_main = False
                        print("3")
                except Exception as e:
                    print("Exception: ", e)
                    print("Malicious Payload Detected")


    # Set up IRQ handler
    bt.irq(bt_irq)


    # Start initial scanning
    print("Scanning for devices...")
    bt.gap_scan(10000)  # Scan for 10 seconds initially
    time.sleep(10)


# Function to connect to WiFi
def STA_Setup(WIFI_SSID, WIFI_PW):
    sta_if = network.WLAN(network.STA_IF)
    if not sta_if.isconnected():
        print('Connecting to WiFi...')
        sta_if.active(True)
        sta_if.connect(WIFI_SSID, WIFI_PW)
        while not sta_if.isconnected():
            pass
    print('WiFi connected! IP:', sta_if.ifconfig())


# Function to connect to MQTT
def connect_mqtt():
    global mqtt_client
    try:
        with open(KEY_FILE, "r") as f:
            key = f.read()
        with open(CERT_FILE, "r") as f:
            cert = f.read()
        mqtt_client = MQTTClient(client_id=MQTT_CLIENT_ID, server=MQTT_HOST, port=MQTT_PORT, keepalive=5000, ssl=True, ssl_params={"cert": cert, "key": key, "server_side": False})
        #mqtt_client.set_buffer_size(1024)  # Set buffer size to 1 KB
        mqtt_client.connect()
        print('MQTT Connected!')
    except Exception as e:
        print('Cannot connect to MQTT:', e)
        raise


# Function to publish a message to MQTT
def pub_msg(msg,key):
    connect_mqtt()
    global mqtt_client
    send_data = {"e": ubinascii.hexlify(aes_encrypt(base64_encode(msg.encode('utf-8')),key)).decode('utf-8')}
    serialized_message = json.dumps(send_data)
    try:
        mqtt_client.publish(MQTT_TOPIC, serialized_message)
        print("Sent:", msg)
        mqtt_client.disconnect()
    except Exception as e:
        print("Exception publish:", e)
        raise


def BLE_Start():
    bt = bluetooth.BLE()
    if not bt.active():
        bt.active(True)
        print("Bluetooth activated.")
    return bt


def BLE_Stop(bt):
    bt.active(False)


# Step 1: Connect to WiFi
STA_Setup(WIFI_SSID, WIFI_PW)


while True:
    WHITE_LED.value(0)
    RED_LED.value(0)
    
    if is_main:
        # Main device operation
        if BUTTON.value() == 0:  # Button pressed
            condition = b"esp_run"
            DHT.measure()
            temperature = DHT.temperature()
            humidity = DHT.humidity()
            
            # Alert system
            if temperature > TEMP_THRESHOLD or humidity > HUMIDITY_THRESHOLD:
                RED_LED.value(1)  # Turn on red LED
                WHITE_LED.value(0)  # Turn off white LED
            else:
                RED_LED.value(0)  # Turn off red LED
                WHITE_LED.value(1)  # Turn on white LED
            
            # Send data to MQTT
            data = {"temperature": temperature, "humidity": humidity, "device_id": "main"}
            msg = json.dumps(data)
            pub_msg(msg,key)
            
            print(f"Temperature: {temperature}, Humidity: {humidity}")
        else:
            condition = b"esp_stop"
        
        # Advertise
        bt = BLE_Start()
        bluetooth_sender(bt)
        BLE_Stop(bt)
        
    else:
        # Backup device operation
        bt = BLE_Start()
        bluetooth_receiver(bt)
        BLE_Stop(bt)
        current_time = time.time()
        if current_time - last_received > 60:  # No signal from main within 10 seconds
            print("No signal from main. Switching to main mode.")
            is_main = True
            bt = BLE_Start()
            bluetooth_sender(bt)
            BLE_Stop(bt)
        
        time.sleep(10)  # Ensure 10-second total cycle for backup
"""
except KeyboardInterrupt:
    print("Program interrupted by user.")
    sta_if.disconnect()
except OSError as e:
    print("Network error occurred:", e)
    sta_if.disconnect()
except Exception as e:
    print("Error:", e)
    sta_if.disconnect()
finally:
    # Ensure both LEDs are turned off upon exit
    RED_LED.value(0)
    WHITE_LED.value(0)
    print("LEDs turned off. Program exiting.")
"""
