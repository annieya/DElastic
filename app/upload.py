from flask import Flask, request, redirect, url_for,current_app
from werkzeug import secure_filename

def upload_sender(uploaded_files,filenames):
	app = current_app._get_current_object()
	filenames = []
	for file in uploaded_files:
		filename = secure_filename(file.filename)
		file.save(app.config['UPLOAD_FOLDER'],file.filename)
		filenames.append(file.filename)
	return filenames