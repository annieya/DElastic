import flask
from flask import render_template, Response, flash
from . import main
import sys
from imp import reload
import os
from .. import action
import json
import csv
from bokeh.io import output_file, show, vplot, hplot, gridplot
from bokeh.models import Legend
from bokeh.embed import components
from bokeh.util.string import encode_utf8
from bokeh.resources import INLINE
from bokeh.plotting import figure
import bokeh.sampledata
from bokeh.charts import Bar, Donut
import pandas as pd
from bokeh.charts.utils import cycle_colors
import pycurl
from io import StringIO, BytesIO
import random
@main.route('/')
def index():
	reload(sys) #解决中文编码
	
	e_location = "127.0.0.1:9203"
	e_index = "logstash-*"
	analysis =action.LogAnalysis(e_location, e_index)
	
	c = pycurl.Curl()
	buf =BytesIO()
	c.setopt(c.URL, 'http://' + e_location + '/' + e_index + '/_search')
	c.setopt(pycurl.CUSTOMREQUEST,"GET")
	c.setopt(c.WRITEFUNCTION, buf.write)
	c.perform()
	results = buf.getvalue()
	results = json.loads(results.decode('utf-8'))
	c.close
	if results["hits"]["total"] == 0:
		flash('you have got no data!')
		return render_template('auth/upload.html')
	else:
		
		#bar1
		actionlist = analysis.actionAgg("action")
		df=pd.DataFrame(actionlist)
		bar1 = Bar(df, label='action', values='size', agg='max', color="green", title="sshd-invalid-passwd_IP", plot_width=600, plot_height=322, legend=False)
		
		script, div = components(bar1)
		'''
		#dount
		label,value,res = analysis.USERAgg("action")
		data = pd.Series(value, index = label)
		pie_chart = Donut(data, plot_width=400, plot_height=300)
		
		script2, div2 = components(pie_chart)
		'''
		#user_ip
		useriplist = analysis.USERIPAgg("action")
		a = list()
		for i in useriplist:
				data = pd.Series(i['value'], index = i['ip'])
				pie_chart = Donut(data, title = i['user'] +'\n'+ ",IP總數:" + str(len(i['value'])), plot_width=190, plot_height=190)
				a.append(pie_chart)
		b=[]
		for i in range(0,len(a),5):
			b.append(a[i:i+5])
		p = gridplot(b)
		
		script3, div3 = components(p)
		
		#INLINE_config
		js_resources = INLINE.render_js()
		css_resources = INLINE.render_css()
		
		#piechart
		labels,values,res = analysis.USERAgg("action")
		colors = []
		for i in labels:
			colors.append("#%06x" % random.randint(0, 0xFFFFFF))
		#colors = [ "#F7464A", "#46BFBD", "#FDB45C", "#FEDCBA","#ABCDEF", "#DDDDDD", "#ABCABC", "#AABEEF", "#EFAAED", "#bebece"]
		count = 0
		for a in res:
			a["color"]=colors[count]
			if count<9:
				count+=1
		#TableAgg
		Usertable = analysis.TableAgg("USERNAME","SUPERUSER")
		
		
		return render_template('index.html',
			plot_script=script,
			plot_div=div,
			pies_script=script3,
			pies_div=div3,
			js_resources=js_resources,
			css_resources=css_resources,
			set=zip(values, labels, colors),
			res=res,
			Usertable = Usertable
		)