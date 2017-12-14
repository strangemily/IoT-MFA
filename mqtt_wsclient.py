#! /usr/bin/python -tt

import paho.mqtt.client as mqtt
import time,json

def on_message(client, userdata, msg):
	sendcommand.payload=msg.payload
	sendcommand.resp=True

def sendcommand(command):
	count=0
	sendcommand.resp=False

	if command == 'getdevstatus':
		sendcommand.payload=json.dumps([['0','Connection Timeout','N/A','0','0',False]])
	elif 'CheckAuthConns#' in command:
		sendcommand.payload=json.dumps(None)
	elif 'ManageAuthConns#' in command:
		sendcommand.payload=json.dumps(None)
	elif 'force_remove#' in command:
		sendcommand.payload=json.dumps(False)

	client.publish(topic="iotmfa/commands", payload = command)
	client.loop_start()
	while True:
		if sendcommand.resp and count<=50:
			client.loop_stop()
			sendcommand.resp=False
			return sendcommand.payload
		elif not sendcommand.resp and count > 50:
			return sendcommand.payload
		else:
			count+=1
			time.sleep(0.1)

client=mqtt.Client()
client.tls_set("./certs/iotmfaca.crt")
client.on_message = on_message
client.connect("18.216.204.249", port=8883, keepalive=60)
client.subscribe(topic='iotmfa/response')
