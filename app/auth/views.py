from flask import render_template, redirect, request, url_for, flash, current_app
from flask_login import login_user, logout_user, login_required, current_user
from . import auth
from .. import db
from ..models import User
from ..email import send_email
from .forms import LoginForm, RegistrationForm
from werkzeug import secure_filename
import os
import pycurl
from io import StringIO, BytesIO
import json
@auth.before_app_request
def before_request():
    if current_user.is_authenticated \
            and not current_user.confirmed \
            and request.endpoint[:5] != 'auth.' \
            and request.endpoint != 'static':
        return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password.')
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm Your Account',
                   'auth/email/confirm', user=user, token=token)
        flash('A confirmation email has been sent to you by email.')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))


@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account',
               'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('main.index'))
	
@auth.route('/upload')
def upload():
    return render_template('auth/upload.html')

@auth.route('/uploader', methods = ['GET', 'POST'])
def uploader():
	app = current_app._get_current_object()
	uploaded_files = request.files.getlist("file[]")
	filenames = []
	if request.method == 'POST':
		for file in uploaded_files:
			filename = secure_filename(file.filename)
			#file.save(file.filename)
			file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
			filenames.append(file.filename)
	flash('file uploaded successfully %s' %filenames)
	#os.system('C:\load.bat')
	return render_template('auth/upload.html')


@auth.route('/table')
def table():
	e_location = "127.0.0.1:9203"
	e_index = "logstash-*"
	
	c = pycurl.Curl()
	buf =BytesIO()
	c.setopt(c.URL, 'http://' + e_location + '/' + e_index + '/_search')
	c.setopt(c.POSTFIELDS, '{"query":{"match_all":{}},"size":20000}')
	c.setopt(c.WRITEFUNCTION, buf.write)
	c.perform()
	results = buf.getvalue()
	results = json.loads(results.decode('utf-8'))
	c.close
	data=results["hits"]["hits"]
	return render_template('auth/table.html',data = data)
	
@auth.route('/time')
def time():
	e_location = "127.0.0.1:9203"
	e_index = "logstash-*"
	
	c = pycurl.Curl()
	buf =BytesIO()
	c.setopt(c.URL, 'http://' + e_location + '/' + e_index + '/_search')
	c.setopt(c.POSTFIELDS, '{"query":{"bool":{"must_not":[{"match":{"USERNAME":"root"}}]}},"size":20000}')
	c.setopt(c.WRITEFUNCTION, buf.write)
	c.perform()
	results = buf.getvalue()
	results = json.loads(results.decode('utf-8'))
	c.close
	
	time=['00','01','02','03','04','05','06']
	res = []
	for i in results["hits"]["hits"]: 
		for t in time:
			if t == str(i['_source']['timestamp'][7:9]):
				res.append(i)
	return render_template('auth/outoftime.html',res = res)

	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
