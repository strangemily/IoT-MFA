#! /usr/bin/python -tt

# Import Libraries
import ssl,requests,random
from flask import Flask, flash, render_template, redirect, request, session, abort
from wtforms import Form, TextField, validators, SubmitField, RadioField
from flask_sqlalchemy import SQLAlchemy
#from textmagic.rest import TextmagicRestClient

# Flask App Declarations
app = Flask(__name__)
app.config.from_object(__name__)
app.config['SECRET_KEY'] = ""

# Flask Database (SQLite - SQLAlchemy) Declarations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./database/iotweb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask HTTPS Condifugration
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain('./certs/iotmfaserver.crt','./certs/iotmfaserver.key')

# API credentials - SMS and Email
#smsapi_client = TextmagicRestClient("","")
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

# Testing Database changes, Remove when deployed
#	def __repr__(self):
#		return '<ID %r User %r Password %r>' % (self.id, self.username, self.password)

# Flask WTForms
class SignupForm(Form):
	username_ui = TextField('Username:', validators=[validators.required()])
	password_ui = TextField('Password:', validators=[validators.required()])
	cfpasswd_ui = TextField('Confirm Password:', validators=[validators.required()])
	email_ui = TextField('Email:', validators=[validators.required()])
	phone_ui = TextField('Phone:', validators=[validators.required()])

class UserRemoveForm(Form):
	user_ui = RadioField('Users', choices=[('1','2')])

class LoginForm(Form):
	username_ui = TextField('Username:', validators=[validators.required()])
	password_ui = TextField('Password:', validators=[validators.required()])

class userVerifyForm(Form):
	otp_ui = TextField('OTP:', validators=[validators.required()])

class userPasswdResetForm(Form):
	password_ui = TextField('Password:', validators=[validators.required()])
	cfpasswd_ui = TextField('Confirm Password:', validators=[validators.required()])
