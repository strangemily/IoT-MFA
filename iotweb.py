#! /usr/bin/python -tt

from configiotweb import *

@app.route("/", methods=['GET','POST'])
def home():
#	print request.environ['REMOTE_ADDR']
	form = LoginForm(request.form)
	if not session.get('logged_in'):
		if not adminCheck():
			flash("Admin not found, Create Admin !")
			session['logged_in'] = True
			return render_template('userSignup.html', form=form)
		else:
			return render_template('userLogin.html', form=form)
	else:
		flash("Logged in, You can perform Priviledged Operations")
		return render_template('landingPage.html')


@app.route('/login', methods=['GET','POST'])
def userLogin():
	if request.form['submit'] == 'Login':
		if validCredentials(request.form['username'], request.form['password']):
#			userLogin.sms_otp = sendSMS()
			userLogin.email_otp = sendEmail()
			form = userVerifyForm(request.form)
			return render_template('userVerify.html', form=form)
		else:
			session['logged_in'] = False
			flash('Wrong Username Password Combination!')
		return home()
	elif request.form['submit'] == 'Reset':
		session['logged_in'] = False
		username_ui = request.form['username']
		if userExists(username_ui):
			flash('Reset Password for user ' + username_ui)
			userLogin.email_otp = sendEmail()
#			userLogin.sms_otp = sendSMS()
			userLogin.username = username_ui
			session['passwd_reset'] = True
			form = userVerifyForm(request.form)
			return render_template('userVerify.html', form=form)
		else:
			flash('User does not exist, enter a valid username')
		return home()

@app.route('/verify', methods=['GET','POST'])
def userVerify():
	if request.form['submit'] == "Verify":
		try:
			if request.form['otp_ui'] == userLogin.email_otp: #Change to userLogin.sms_otp for SMS
				if session.has_key('passwd_reset') and session['passwd_reset'] == True:
					flash('Enter new Password')
					session['passwd_reset'] = False
					form = userPasswdResetForm(request.form)
					return render_template('userPasswdReset.html', form=form)
				else:
					session['logged_in'] = True
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
			if passwdMatch(password_ui, cfpasswd_ui):
					userdb = User.query.filter_by(username=userLogin.username).first()
					userdb.password = password_ui
					db.session.commit()
					flash(User.query.all())
					flash('Password changed, Login with new credentials')
					session['logged_in'] = False
			else:
				flash('Passwords dont match, reset failed')
				session['logged_in'] = False
		except AttributeError:
			pass
	else:
		flash('Invalid Request')
	return home()

@app.route('/landingpage', methods=['GET','POST'])
def landingPage():
	if request.form['submit'] == 'Add User':
		form = SignupForm(request.form)
		return render_template('userSignup.html', form=form)
	elif request.form['submit'] == 'Remove User':
		userlist=[]
		userlist_db = db.session.query(User.id,User.username).all()
		for user_db in userlist_db:
			if user_db.id != 1:
				userlist.append(user_db.username)
		form = UserRemoveForm(request.form)
		return render_template('userRemove.html', form=form, userlist=userlist)
	elif request.form['submit'] == 'Access Devices':
		return redirect('/dummy', code=302)
	elif request.form['submit'] == 'Disconnect':
		return redirect('/dummy', code=302)
	elif request.form['submit'] == 'Logout':
		session['logged_in'] = False
		return home()

@app.route('/dummy', methods=['GET','POST'])
def dummy():
	return "Not Implemented"

@app.route('/userremove', methods=['GET','POST'])
def userRemove():
	if request.form['submit'] == 'Remove':
		username_ui=request.form['username_ui']
		if userExists(username_ui) and not adminControl(username_ui):
			db.session.delete(User.query.filter(User.username == username_ui).first())
			db.session.commit()
			flash(User.query.all())
			flash('User ' + username_ui + ' removed')
		else:
			flash('Invalid Request')
	else:
		flash('Invalid Request')
	return home()

@app.route('/signup', methods=['GET','POST'])
def userSignup():
	form = SignupForm(request.form)
	if session.get('logged_in') and request.form['submit'] == "Sign up":
		username_ui=request.form['username_ui']
		password_ui=request.form['password_ui']
		cfpasswd_ui=request.form['cfpasswd_ui']
		email_ui=request.form['email_ui']
		phone_ui=request.form['phone_ui']

		if form.validate():
			if userExists(username_ui):
				flash('Username Exists')
				return render_template('userSignup.html', form=form)
			elif not passwdMatch(password_ui, cfpasswd_ui):
				flash('Passwords Not Matched')
				return render_template('userSignup.html', form=form)
			else:
				userdb = User(username = username_ui, password = password_ui, email = email_ui, phone = phone_ui)
				db.session.add(userdb)
				db.session.commit()
				flash(User.query.all())
		else:
			flash('All the form fields are required. ')
			return render_template('userSignup.html', form=form)
	else:
		flash('Invalid Request')
	return home()

def userExists(username_ui):
	return db.session.query(db.exists().where(User.username == username_ui)).scalar()

def passwdMatch(password_ui,cfpasswd_ui):
	if cfpasswd_ui == password_ui:
		return True
	else:
		return False

def adminCheck():
	return db.session.query(db.exists().where(User.id == '1')).scalar()

def adminControl(username_ui):
	return db.session.query(User.username).filter(User.username == username_ui, User.id == 1).first()

def validCredentials(cwuname, cwpasswd):
	return db.session.query(User).filter(User.username == cwuname, User.password == cwpasswd).first()

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

if __name__ == "__main__":
	db.create_all()
	app.run(host='0.0.0.0', port=443, threaded=True, debug=True, ssl_context=context)
