# import pyes
import pycurl
from io import StringIO, BytesIO
import json
import csv
import bokeh.sampledata
from bokeh.charts import Bar, output_file
import pandas as pd
import re


class LogAnalysis:
	def __init__(self, e_location, e_index):
		self.e_location = e_location
		self.e_index = e_index
		
	def actionAgg(self,action):
		c = pycurl.Curl()
		buf =BytesIO()
		c.setopt(c.URL, 'http://' + self.e_location + '/' + self.e_index + '/_search')
		c.setopt(c.POSTFIELDS, '{"size":0,"query":{"filtered":{"query":{"query_string":{"query":"sshd-invalid-passwd","analyze_wildcard":true}},"filter":{"bool":{"must":[],"must_not":[]}}}},"aggs":{"2":{"terms":{"field":"IP.raw","size":0,"order":{"_count":"desc"}}}}}')
		c.setopt(c.WRITEFUNCTION, buf.write)
		c.perform()
		results = buf.getvalue()
		results = json.loads(results.decode('utf-8'))
		c.close

		# print json.dumps(results, indent=4)
		res = list()
		for i in results['aggregations']['2']['buckets']:
			r = dict()
			r["action"]=i['key']
			r["size"]=i['doc_count']
			res.append(r)
		return res
		
	def USERAgg(self,counts):
		c = pycurl.Curl()
		buf =BytesIO()
		c.setopt(c.URL, 'http://' + self.e_location + '/' + self.e_index + '/_search')
		c.setopt(c.POSTFIELDS, '{"size":0,"query":{"filtered":{"query":{"query_string":{"analyze_wildcard":true,"query":"sshd-passwd-accept"}},"filter":{"bool":{"must":[],"must_not":[{"match":{"USERNAME":"root"}}]}}}},"aggs":{"2":{"terms":{"field":"USERNAME.raw","size":0,"order":{"_count":"desc"}}}}}')
		c.setopt(c.WRITEFUNCTION, buf.write)
		c.perform()
		results = buf.getvalue()
		results = json.loads(results.decode('utf-8'))
		c.close

		# print json.dumps(results, indent=4)
		total=float()
		for i in results['aggregations']['2']['buckets']:
			total += i['doc_count']
		labels = list()
		values = list()
		res = list()
		for i in results['aggregations']['2']['buckets']:
			labels.append(i['key'])
			a = float()
			a = round((i['doc_count'] / total ),4)
			values.append(str(a * 100))
			r = dict()
			r["label"]=i['key']
			r["value"]=i['doc_count']
			res.append(r)
		return labels,values,res
		
	def USERIPAgg(self,action):
		c = pycurl.Curl()
		buf = BytesIO()
		c.setopt(c.URL, 'http://' + self.e_location + '/' + self.e_index + '/_search')
		c.setopt(c.POSTFIELDS, '{"size":0,"aggs":{"counts":{"terms":{"field":"USERNAME.raw"}}}}')
		c.setopt(c.WRITEFUNCTION, buf.write)
		c.perform()
		results = buf.getvalue()
		results = json.loads(results.decode('utf-8'))
		c.close

		# print json.dumps(results, indent=4)
		res = list()
		for i in results['aggregations']['counts']['buckets']:
			c = pycurl.Curl()
			buf = BytesIO()
			c.setopt(c.URL, 'http://' + self.e_location + '/' + self.e_index + '/_search')
			c.setopt(c.POSTFIELDS, '{"query":{"match":{"USERNAME":"'+ i['key'] +'"}},"aggs":{"counts":{"terms":{"field":"IP.raw","size":0}}}}')
			c.setopt(c.WRITEFUNCTION, buf.write)
			c.perform()
			results = buf.getvalue()
			results = json.loads(results.decode('utf-8'))
			c.close
			
			r = dict()
			r['user']=i['key']
			iplist = list()
			ipvalue = list()
			for z in results['aggregations']['counts']['buckets']:
					iplist.append(str(z['key'])+"("+str(z['doc_count'])+")")
					ipvalue.append(z['doc_count'])
			r['ip'] = iplist
			r['value'] = ipvalue
			res.append(r)
		return res
		
	def TableAgg(self,USERNAME,SUPERUSER):
		c = pycurl.Curl()
		buf = BytesIO()
		c.setopt(c.URL, 'http://' + self.e_location + '/' + self.e_index + '/_search')
		c.setopt(c.POSTFIELDS, '{"size":0,"query":{"bool":{"must_not":[{"match":{"USERNAME":"root"}}]}},"aggs":{"counts":{"terms":{"field":"USERNAME.raw","size":0}}}}')
		c.setopt(c.WRITEFUNCTION, buf.write)
		c.perform()
		results = buf.getvalue() 
		results = json.loads(results.decode('utf-8'))
		c.close

		# print json.dumps(results, indent=4)
		res = list()
		for i in results['aggregations']['counts']['buckets']:
			c = pycurl.Curl()
			buf = BytesIO()
			c.setopt(c.URL, 'http://' + self.e_location + '/' + self.e_index + '/_search')
			c.setopt(c.POSTFIELDS, '{"query":{"bool":{"must":[{"match":{"USERNAME":"'+ i['key'] +'"}}]}},"aggs":{"counts":{"terms":{"field":"SUPERUSER.raw","size":0}}}}')
			c.setopt(c.WRITEFUNCTION, buf.write)
			c.perform()
			results = buf.getvalue()
			results = json.loads(results.decode('utf-8'))
			c.close
			# print json.dumps(results, indent=4)
			for b in results['aggregations']['counts']['buckets']:
				c= pycurl.Curl()
				buf = BytesIO()
				c.setopt(c.URL, 'http://' + self.e_location + '/' + self.e_index + '/_search')
				c.setopt(c.POSTFIELDS, '{"query":{"bool":{"must":[{"match":{"USERNAME":"'+ i['key'] +'"}},{"match":{"SUPERUSER":"'+ b['key'] +'"}}]}},"aggs":{"counts":{"terms":{"field":"timestamp.raw","size":0}}}}')
				c.setopt(c.WRITEFUNCTION, buf.write)
				c.perform()
				results = buf.getvalue()
				results = json.loads(results.decode('utf-8'))
				c.close
				# print json.dumps(results, indent=4)
				for z in results['aggregations']['counts']['buckets']:
					r = dict()
					r["USERNAME"]=i['key']
					r['SUPERUSER']=b['key']
					r["timestamp"]=z['key']
					r["size"]=z['doc_count']
					res.append(r)
		return res