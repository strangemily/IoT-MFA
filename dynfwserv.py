#!/usr/bin/python -tt

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from netfilter.rule import Rule,Match
from netfilter.table import Table,IptablesError
import time

app = Flask(__name__)
app.config.from_object(__name__)
app.config['SECRET_KEY'] = 'DOYOUEVENDYNFWBRO'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./database/iotweb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(64), unique=True, nullable=False)
	password = db.Column(db.String(64), nullable=False)
	email = db.Column(db.String(64), nullable=False)
	phone = db.Column(db.String(64), nullable=False)

	def __repr__(self):
		return '<ID %r User %r Password %r>' % (self.id, self.username, self.password)

class IoT(db.Model):
	mac_addr = db.Column(db.String(64), primary_key=True)
	ip_addr = db.Column(db.String(64), nullable=False)
	dev_status = db.Column(db.String(64), nullable=False)
	lease_time = db.Column(db.String(64), nullable=False)
	dev_name = db.Column(db.String(64), nullable=False)

	def __repr__(self):
		return '<MAC %r IP %r Status %r Lease %r Device %r>' % (self.mac_addr, self.ip_addr, self.dev_status, self.lease_time, self.dev_name)

class AuthConns(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(64), nullable=False)
	ip_addr = db.Column(db.String(64), nullable=False)
	ip_port = db.Column(db.Integer, nullable=True)
	sessiontime = db.Column(db.String(64), nullable=False)
	fw_status = db.Column(db.Boolean())
	port_status = db.Column(db.Boolean())

	def __repr__(self):
		return '<User %r IP %r Port %r Time %r>' % (self.username, self.ip_addr, self.ip_port, self.sessiontime)

db.create_all()

def print_table():
	print AuthConns.query.all()

def rule_manager():
	filtable=Table('filter')
	while True:
		for row in db.session.query(AuthConns):
			if int(row.sessiontime) <= int(time.time()):
				try:
					rule0=Rule(
						jump='ACCEPT',
						protocol='udp',
						matches=[Match('udp','--dst '+str(row.ip_addr))])
					filtable.delete_rule('FORWARD',rule0)
				except IptablesError as e:
					pass
				db.session.delete(AuthConns.query.filter(AuthConns.id == row.id).first())
			elif not row.fw_status:
				rule0=Rule(
						jump='ACCEPT',
						protocol='udp',
						matches=[Match('udp','--dst '+str(row.ip_addr))])
				filtable.prepend_rule('FORWARD',rule0)
				cwfwrule = AuthConns.query.filter_by(id=row.id).first()
				cwferule.fw_status = True
			elif not row.ip_port:
				log_lookup()
				manage_logging()
			else:
				pass
		db.session.commit()
		time.sleep(2)

def log_lookup():
	with open('/var/log/firewall','r') as f:
		lines = f.readlines()
		for line in lines:
			cwport=int(line.split("DPT=")[1].split()[0])
			cwip=line.split("DST=")[1].split()[0]
			authconndb = AuthConns.query.filter_by(ip_addr=cwip).filter_by(ip_port=None).first()
			authconndb.ip_port = cwport
	open('/var/log/firewall','w').close()
	return


def manage_logging():
	filtable=Table('filter')
	for row in db.session.query(AuthConns):
		if row.ip_port and not row.port_status:

			rule0=Rule(
				jump='ACCEPT',
				protocol='udp',
				matches=[Match('udp','--dst '+str(row.ip_addr)+' --dport '+str(row.ip_port))])
			filtable.prepend_rule('FORWARD',rule0)

			try:
				rule1=Rule(
					jump='LOG',
					protocol='udp',
					matches=[Match('udp','--dst '+str(row.ip_addr)),Match('limit','--limit 1/hour --limit-burst 1')])
				filtable.delete_rule('FORWARD',rule1)
			except IptablesError as e:
				pass
			try:
				rule2=Rule(
					jump='ACCEPT',
					protocol='udp',
					matches=[Match('udp','--dst '+str(row.ip_addr))])
				filtable.delete_rule('FORWARD',rule2)
			except IptablesError as e:
				pass

			row.port_status = True

		else:
			pass


def force_add(ip_addr):
	filtable=Table('filter')
	rule0=Rule(
		jump='ACCEPT',
		protocol='udp',
		matches=[Match('udp','--dst '+ip_addr)])
	filtable.prepend_rule('FORWARD',rule0)

	rule1=Rule(
		jump='LOG',
		protocol='udp',
		matches=[Match('udp','--dst '+ip_addr),Match('limit','--limit 1/hour --limit-burst 1')])
	filtable.prepend_rule('FORWARD',rule1)


def force_remove(ip_addr):
	filtable=Table('filter')
	try:
		rule0=Rule(
			jump='ACCEPT',
			protocol='udp',
			matches=[Match('udp','--dst '+str(ip_addr))])
		filtable.delete_rule('FORWARD',rule0)
	except IptablesError as e:
		pass
