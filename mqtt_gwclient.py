#! /usr/bin/python -tt

import paho.mqtt.client as mqtt
import arpreq,json
from dynfwserv import *

def on_message(client, userdata, msg):
	if msg.payload == 'getdevstatus':
		getDevStatus()

	elif 'force_remove#' in msg.payload:
		req=msg.payload.split('#')
		forceRemoveFw(req[1],req[2])

	elif 'CheckAuthConns#' in msg.payload:
		req=msg.payload.split('#')
		checkAuthConns(req[1],req[2])

	elif 'ManageAuthConns#' in msg.payload:
		req=msg.payload.split('#')
		manageAuthConns(req[1],req[2],req[3])

def sendresponse(response):
	client.publish(topic="iotmfa/response", payload = response)

def manageAuthConns(cwusername,cwip_addr,cwsessiontime):
	if AuthConns.query.filter_by(username = cwusername,ip_addr = cwip_addr).scalar():
		authconndb = AuthConns.query.filter_by(username = cwusername,ip_addr = cwip_addr).first()
		authconndb.sessiontime = int(cwsessiontime)
		db.session.commit()
		sendresponse(json.dumps(time.strftime('%H:%M:%S %d %b %Y',time.gmtime(float(AuthConns.query.filter_by(username = cwusername,ip_addr = cwip_addr).first().sessiontime)))))
	else:
		force_add(cwip_addr)
		db.session.add(AuthConns(username=cwusername,ip_addr=cwip_addr,sessiontime=cwsessiontime,fw_status=True))
		db.session.commit()
		sendresponse(json.dumps(time.strftime('%H:%M:%S %d %b %Y',time.gmtime(float(AuthConns.query.filter_by(username = cwusername,ip_addr = cwip_addr).first().sessiontime)))))

def checkAuthConns(cwusername,cwip_addr):
	if AuthConns.query.filter_by(username = cwusername,ip_addr = cwip_addr).first():
		sendresponse(json.dumps(time.strftime('%H:%M:%S %d %b %Y',time.gmtime(float(AuthConns.query.filter_by(username = cwusername,ip_addr = cwip_addr).first().sessiontime)))))
	else:
		sendresponse(json.dumps(None))

def forceRemoveFw(cwusername,cwip_addr):
	force_remove(cwip_addr)
	for row in db.session.query(AuthConns):
		if row.username == cwusername and row.ip_addr == cwip_addr:
			db.session.delete(AuthConns.query.filter(AuthConns.id == row.id).first())
	db.session.commit()
	sendresponse(json.dumps(True))

def getDevStatus():
	data=[]
	lease=[]
	with open ('/var/lib/misc/dnsmasq.leases') as f:
		data=f.readlines()
		for line in data:
			if arpreq.arpreq(line.strip('\n').split()[2]):
				lease.append(line.strip('\n').split()+[True])
			else:
				lease.append(line.strip('\n').split()+[False])
	sendresponse(json.dumps(lease))


db.create_all()
client=mqtt.Client()
client.tls_set("./certs/iotmfaca.crt")
client.on_message = on_message
client.connect("18.216.204.249", port=8883, keepalive=60)
client.subscribe(topic="iotmfa/commands")
client.loop_forever()
