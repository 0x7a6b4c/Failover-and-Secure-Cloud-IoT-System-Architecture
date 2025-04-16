import json
import boto3
from botocore.exceptions import ClientError
import base64
from Crypto.Cipher import AES
from datetime import datetime


def aes_decrypt(key, encrypted_data_hex):
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes long.")


    encrypted_data = bytes.fromhex(encrypted_data_hex)
    cipher = AES.new(key.encode("utf-8"), AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted_data)
    padding_length = decrypted[-1]
    return decrypted[:-padding_length]


def get_secret(session):
    secret_name = ""
    region_name = "" 
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
try:
    	get_secret_value_response = client.get_secret_value(
        	SecretId=secret_name
    	)
	except ClientError as e:
    	raise e
 
	secret = get_secret_value_response['SecretString']
	return secret
 
 
def lambda_handler(event, context):
	session = boto3.session.Session()
	secret = json.loads(get_secret(session))
 
	encrypted = event.get("e")
	decrypted_base64 = aes_decrypt(secret['key'], encrypted)
	decrypted_message = base64.b64decode(decrypted_base64).decode('utf-8')
	data = json.loads(decrypted_message)
	
	device_id = data.get("device_id")
	humidity = data.get("humidity")
	temperature = data.get("temperature")
    	
	if not (device_id and humidity and temperature):
    	raise ValueError("Missing required fields in the message.")
 
	database_name = 'IoTDatabase'
	table_name = 'weatherData'
 
	current_time = str(int(datetime.now().timestamp() * 1000))  # Unix epoch time in milliseconds
	record = {
    	"Dimensions": [
        	{"Name": "DeviceID", "Value": device_id},
    	],
    	"MeasureName": "HumidityTemperature",
	    "MeasureValueType": "MULTI",
    	"MeasureValues": [
        	{"Name": "Humidity", "Value": str(humidity), "Type": "DOUBLE"},
        	{"Name": "Temperature", "Value": str(temperature), "Type": "DOUBLE"}
    	],
    	"Time": current_time
	}
    try:
    	timestream_client = boto3.client('timestream-write')
    	timestream_client.write_records(
        	DatabaseName=database_name,
        	TableName=table_name,
        	Records=[record]
    	)
    	return {
            "statusCode": 200,
        	"body": json.dumps({"message": "Item created in DB"})
    	}
	except Exception as e:
    	return {
        	"statusCode": 500,
        	"body": json.dumps({"error": "Failed to create item in DB"})
    	}
