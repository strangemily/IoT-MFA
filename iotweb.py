#! /usr/bin/python -tt

from configiotweb import *
import firewalliot

@app.route("/", methods=['GET','POST'])
def home():
#	print request.environ['REMOTE_ADDR']
	if not session.get('logged_in'):
		if not adminCheck():
			flash("Admin not found, Create Admin !")
			session['init_session'] = True
			session['logged_in'] = True
			return render_template('userSignup.html', set_ui='')
		else:
			return render_template('userLogin.html')
	else:
		flash("Logged in, You can perform Priviledged Operations")
		return render_template('landingPage.html')

@app.route('/login', methods=['GET','POST'])
def userLogin():
	if request.form['submit'] == 'Login':
		if validCredentials(request.form['username'], request.form['password']):
#			userLogin.sms_otp = sendSMS()
			userLogin.email_otp = sendEmail()
			userLogin.username = request.form['username']
			return render_template('userVerify.html')
		else:
			session['logged_in'] = False
			flash('Wrong Username Password Combination!')
	elif request.form['submit'] == 'Reset':
		session['logged_in'] = False
		username_ui = request.form['username']
		if userExists(username_ui):
			flash('Reset Password for user ' + username_ui)
			userLogin.email_otp = sendEmail()
#			userLogin.sms_otp = sendSMS()
			userLogin.username = username_ui
			session['passwd_reset'] = True
			return render_template('userVerify.html')
		else:
			flash('User does not exist, enter a valid username')
	else:
		session['logged_in'] = False
		flash('Invalid request')
	return home()

@app.route('/verify', methods=['GET','POST'])
def userVerify():
	if request.form['submit'] == "Verify":
		try:
			if request.form['otp_ui'] == userLogin.email_otp: #Change to userLogin.sms_otp for SMS
				if session.has_key('passwd_reset') and session['passwd_reset'] == True:
					flash('Enter new Password')
					session['passwd_reset'] = False
					return render_template('userPasswdReset.html')
				else:
					session['logged_in'] = True
					session['username'] = userLogin.username
					accessDevices.display_iot=[]
					accessDevices.access_device=False
			else:
				session['logged_in'] = False
				flash('Wrong OTP!')
		except AttributeError:
			pass
	elif request.form['submit'] == "Cancel":
		flash('Operation verification Cancelled')
		session['logged_in'] = False
	else:
		flash('Invalid Request')
		session['logged_in'] = False
	return home()

@app.route('/passwdreset', methods=['GET','POST'])
def passwdreset():
	if request.form['submit'] == 'Reset':
		try:
			password_ui=request.form['password_ui']
			cfpasswd_ui=request.form['cfpasswd_ui']
			if entityMatch(password_ui, cfpasswd_ui) and passwdCmplxCheck(password_ui):
					userdb = User.query.filter_by(username=userLogin.username).first()
					userdb.password = bcrypt.hashpw(str(password_ui), bcrypt.gensalt())
					db.session.commit()
					flash(User.query.all())
					flash('Password changed, Login with new credentials')
					session['logged_in'] = False
			else:
				flash('Check password complexity requirements and/or matching')
				return render_template('userPasswdReset.html')
		except AttributeError:
			pass
	else:
		flash('Invalid Request')
	return home()

@app.route('/landingpage', methods=['GET','POST'])
def landingPage():
	if request.form['submit'] == 'Add User':
		return render_template('userSignup.html', set_ui='')
	elif request.form['submit'] == 'Remove User':
		userlist=[]
		userlist_db = db.session.query(User.id,User.username).all()
		for user_db in userlist_db:
			if user_db.id != 1 and user_db.username != session['username']:
				userlist.append(user_db.username)
		return render_template('userRemove.html', userlist=userlist)
	elif request.form['submit'] == 'IoT Portal':
		accessDevices.display_iot=[]
		if not hasattr(accessDevices,'access_device'):
			accessDevices.access_device=False

		lease=renewLeasedIPMAC()
		for record in lease:
			if record.dev_status == '0':
				accessDevices.display_iot.append([record.mac_addr,record.ip_addr,'Offline'])
			else:
				accessDevices.display_iot.append([record.mac_addr,record.ip_addr,'Online'])
		return render_template('accessDevices.html', display_iot=accessDevices.display_iot, access_device=accessDevices.access_device)
	elif request.form['submit'] == 'Logout':
		session['logged_in'] = False
		session['username'] = ''
		accessDevices.display_iot=[]
		accessDevices.access_device=False

		return home()
	else:
		session['logged_in'] = False
		flash('Invalid Request')
		return home()

@app.route('/dummy', methods=['GET','POST'])
def dummy():
	return "Not Implemented"

@app.route('/accessdevices', methods=['GET','POST'])
def accessDevices():
	if not hasattr(accessDevices,'display_iot'):
		accessDevices.display_iot=[]
	if not hasattr(accessDevices,'access_device'):
		accessDevices.access_device=False

	if request.form['submit'] == 'Cancel':
		return render_template('landingPage.html')
	elif request.form['submit'] == 'Refresh':
		accessDevices.display_iot=[]
		lease=renewLeasedIPMAC()
		for record in lease:
			if record.dev_status == '0':
				accessDevices.display_iot.append([record.mac_addr,record.ip_addr,'Offline'])
			else:
				accessDevices.display_iot.append([record.mac_addr,record.ip_addr,'Online'])
		return render_template('accessDevices.html', display_iot=accessDevices.display_iot, access_device=accessDevices.access_device)
	elif request.form['submit'] == 'Disconnect':
		accessDevices.access_device=False
		firewalliot.block_rules()
		return render_template('accessDevices.html', display_iot=accessDevices.display_iot, access_device=accessDevices.access_device)
	elif request.form['submit'] == 'Access':
		accessDevices.access_device=True
		firewalliot.allow_rules()
		return render_template('accessDevices.html', display_iot=accessDevices.display_iot, access_device=accessDevices.access_device)
	elif request.form['submit'] == 'IoT Portal':
		pass
	else:
		flash('Invalid Request')

@app.route('/userremove', methods=['GET','POST'])
def userRemove():
	if request.form['submit'] == 'Remove' and request.form.has_key('username_ui'):
		username_ui=request.form['username_ui']
		if userExists(username_ui) and not adminControl(username_ui) and not selfIdentify(username_ui):
			db.session.delete(User.query.filter(User.username == username_ui).first())
			db.session.commit()
			flash(User.query.all())
			flash('User ' + username_ui + ' removed')
		else:
			flash('Invalid Request')
	elif request.form['submit'] == 'Cancel':
		flash('Operation User Removal Cancelled')
	else:
		flash('Invalid Request')
	return home()

@app.route('/signup', methods=['GET','POST'])
def userSignup():
	if session.get('logged_in') and request.form['submit'] == "Sign up":
		username_ui=request.form['username_ui']
		password_ui=request.form['password_ui']
		cfpasswd_ui=request.form['cfpasswd_ui']
		email_ui=request.form['email_ui']
		cfemail_ui=request.form['cfemail_ui']
		phone_ui=request.form['phone_ui']
		cfphone_ui=request.form['cfphone_ui']

		if all (request.form.get(keys) for keys in ('username_ui','password_ui','cfpasswd_ui','email_ui','cfemail_ui','phone_ui','cfphone_ui')):
			set_ui=[username_ui, email_ui, cfemail_ui, phone_ui, cfphone_ui]
			if userExists(username_ui):
				flash('Username Exists, Try another Username')
				return render_template('userSignup.html', set_ui=set_ui)
			elif not entityMatch(password_ui, cfpasswd_ui) or not passwdCmplxCheck(password_ui):
				flash('Invalid Password')
				return render_template('userSignup.html', set_ui=set_ui)
			elif not entityMatch(email_ui, cfemail_ui) or not emailCheck(email_ui):
				flash('Invalid Email')
				return render_template('userSignup.html', set_ui=set_ui)
			elif not entityMatch(phone_ui, cfphone_ui) or not phoneCheck(phone_ui):
				flash('Invalid Phone')
				return render_template('userSignup.html', set_ui=set_ui)
			else:
				db.session.add(User(username = username_ui, password = bcrypt.hashpw(str(password_ui), bcrypt.gensalt()), email = email_ui, phone = phone_ui))
				db.session.commit()
				if session.has_key('init_session') and session['init_session']:
					session['username'] = username_ui
					session['init_session'] = False
				flash(User.query.all())
		else:
			flash('All the form fields are required. ')
			set_ui=[username_ui, email_ui, cfemail_ui, phone_ui, cfphone_ui]
			return render_template('userSignup.html', set_ui=set_ui)
	elif request.form['submit'] == 'Cancel':
		flash('Operation User Add Cancelled')
	else:
		flash('Invalid Request')
	return home()

def userExists(username_ui):
	return db.session.query(db.exists().where(User.username == username_ui)).scalar()

def entityMatch(entity_ui,cfentity_ui):
	return (cfentity_ui == entity_ui)

def emailCheck(email_ui):
	return (re.compile(r"[^@\s]+@[a-zA-Z0-9\.-]+\.[a-zA-Z0-9]+$").match(email_ui))

def phoneCheck(phone_ui):
	return (phone_ui.isdigit() and len(phone_ui) == 10)

def passwdCmplxCheck(password_ui):
	return (((re.search(r"[A-Z]", password_ui) is not None) and (re.search(r"[0-9]", password_ui) is not None) and (re.search(r"[a-z]", password_ui) is not None) and (re.search(r"[ !#$%&@'()*+,-./[\\\]^_`{|}~"+r'"]', password_ui) is not None) and len(password_ui)>=8))

def adminCheck():
	return db.session.query(db.exists().where(User.id == '1')).scalar()

def adminControl(username_ui):
	return db.session.query(User.username).filter(User.username == username_ui, User.id == 1).first()

def selfIdentify(username_ui):
	return (username_ui == session['username'])

def validCredentials(cwuname, cwpasswd):
	cwdbentry = db.session.query(User.password).filter(User.username == cwuname).first()
	if hasattr(cwdbentry, 'password'):
		return (bcrypt.hashpw(str(cwpasswd), str(cwdbentry.password)) == str(cwdbentry.password))
	else:
		return False

def sendSMS():
	sms_otp = '{0:06d}'.format(random.randint(0,999999))
#	smsapi_result = smsapi_client.messages.create(phones=default_phone, text=sms_otp)
	return sms_otp

def sendEmail():
	email_otp = '{0:06d}'.format(random.randint(0,999999))
	requests.post(
	emailapi_link,
	auth=("api", emailapi_key),
	data={"from": emailapi_from,
		"to": default_name + " <" + default_email +">",
		"subject": "IoT MFA OTP",
		"text": "Please enter the following OTP:" + email_otp})
	return email_otp


def renewLeasedIPMAC():
	lease=[]
	with open ('/var/lib/misc/dnsmasq.leases') as f:
		data=f.readlines()
		for line in data:
			if arpreq.arpreq(line.strip('\n').split()[2]):
				lease.append(line.strip('\n').split()+[True])
			else:
				lease.append(line.strip('\n').split()+[False])

	for record in lease:
		if db.session.query(db.exists().where(IoT.mac_addr == record[1])).scalar():
			iotdb = IoT.query.filter_by(mac_addr = record[1]).first()
			iotdb.ip_addr = record[2]
			iotdb.dev_status = record[5]
			iotdb.lease_time = record[0]
			iotdb.dev_name = record[3]
			db.session.commit()
		else:
			db.session.add(IoT(mac_addr = record[1], ip_addr = record[2], dev_status = record[5], lease_time = record[0], dev_name = record[3]))
			db.session.commit()

	return IoT.query.all()

if __name__ == "__main__":
	db.create_all()
	firewalliot.block_rules()
	app.run(host='0.0.0.0', port=443, threaded=True, debug=True, ssl_context=context)
