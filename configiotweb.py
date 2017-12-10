#! /usr/bin/python -tt

# Import Libraries
import ssl,requests,random,bcrypt,re,arpreq
from flask import Flask, flash, render_template, redirect, request, session, abort
from flask_sqlalchemy import SQLAlchemy
#from textmagic.rest import TextmagicRestClient

# Flask App Declarations
app = Flask(__name__)
app.config.from_object(__name__)
app.config['SECRET_KEY'] = ''

# Flask Database (SQLite - SQLAlchemy) Declarations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./database/iotweb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask HTTPS Condifugration
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain('./certs/iotmfaserver.crt','./certs/iotmfaserver.key')

# API credentials - SMS and Email
#smsapi_client = TextmagicRestClient('','')
emailapi_link = ""
emailapi_from = ""
emailapi_key = ""

# Default User for Testing SMS and EMail API
default_name = ""
default_phone = ""
default_email = ""

# SQL database model
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
		return '<User %r IP %r Time %r>' % (self.username, self.ip_addr, self.sessiontime)
