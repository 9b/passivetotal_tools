#!/usr/bin/env python

"""
Copyright (c) 2015, PassiveTotal LLC.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import requests
import json
import logging
import sys

class set_check(object):
	"""Python decorator to perform field checks and input tests
	for calls where data is being POSTed to the API"""
	def __init__(self, field, test):
		self.field = field
		self.test = test
	def __call__(self, func):
		def wrapped(*args, **kwargs):
			if self.field not in kwargs.keys():
				raise Exception('%s is a required field' % self.field)
			if kwargs[self.field] not in self.test:
				raise Exception('%s is not a valid value (%s)' % (kwargs[self.field], str(self.test)))
			return func(*args, **kwargs)
		return wrapped

class PassiveTotal(object):
	"""Python helper library built on top of the PassiveTotal (www.passivetotal.org)
	service API. For updated documentation, head over to www.passivetotal.org/api.
	"""	
	def __init__(self, api_key):
		"""Initialize our object with a couple helpers and known-states
		@param	api_key	string	valid API key for PassiveTotal
		"""
		self._api_key = api_key
		
		self._endpoint = 'https://www.passivetotal.org/api/v1/'
		self._valid_methods = ['GET', 'POST']
		self._generic_get_types = ['metadata', 'passive', 'subdomains', \
							 'unique', 'classification', 'sinkhole' \
							 'dynamic', 'ever_compromised', 'watching']
		self._generic_post_types = ['classification', 'sinkhole', 'dynamic' \
									'ever_compromised', 'watching']
		self._classifications = ['targeted', 'crime', 'multiple', 'benign']
		self._logger = logging.getLogger('PassiveTotal')
		
	@property
	def endpoint(self):
		"""Endpoint getter"""
		return self._endpoint
		
	@endpoint.setter
	def endpoint(self, endpoint):
		"""PassiveTotal offers different versions of the API, so a user
		could in theory could be using something beyond the latest. 
		
		@param	endpoint	string	fully qualified URL of the API
		@returns	bool	whether or not the setting was successful
		"""
		if endpoint.split(':')[0].lower() not in ['http', 'https']:
			raise Exception('Endpoint must start with HTTP/HTTPS')
		if not endpoint.endswith('/'):
			endpoint += '/'
		self._endpoint = endpoint
		
		return True
	
	@property
	def logger(self):
		"""Logger getter"""
		return self._logger.getEffectiveLevel()
		
	@logger.setter	
	def logger(self, level):
		"""Simple logger to provide feedback when using the library"""
		logger = logging.getLogger('PassiveTotal')
		if level == "INFO":
			logger.setLevel(logging.INFO)
		elif level == "WARN":
			logger.setLevel(logging.WARN)
		elif level == "DEBUG":
			logger.setLevel(logging.DEBUG)
		elif level == "ERROR":
			logger.setLevel(logging.ERROR)
		else:
			raise Exception('%s was not a valid logging level' % level)
		format = logging.Formatter('\033[1;32m%(levelname)-5s %(module)s:%(funcName)s():%(lineno)d %(asctime)s\033[0m| %(message)s')
		shandler = logging.StreamHandler(sys.stdout)
		shandler.setFormatter(format)
		logger.addHandler(shandler)
		return logger
		
	# Pass-through GET methods
	def get_metadata(self, query_value):
		return self._router('GET', 'metadata', query_value)
	def get_passive(self, query_value):
		return self._router('GET', 'passive', query_value)
	def get_subdomains(self, query_value): 
		return self._router('GET', 'subdomains', query_value)
	def get_unique(self, query_value):
		return self._router('GET', 'unique', query_value)
	def get_classification(self, query_value):
		return self._router('GET', 'classification', query_value)
	def get_user_tags(self, query_value):
		return self._router('GET', 'user/tags', query_value)
	def get_sinkhole(self, query_value):
		return self._router('GET', 'sinkhole', query_value)
	def get_ever_compromised(self, query_value):
		return self._router('GET', 'ever_compromised', query_value)
	def get_dynamic(self, query_value):
		return self._router('GET', 'dynamic', query_value)
	def get_watching(self, query_value):
		return self._router('GET', 'watching', query_value)
		
	# Pass-through POST methods
	@set_check('classification', ['targeted', 'crime', 'multiple', 'benign'])
	def set_classification(self, query_value, **kwargs):
		return self._router('POST', 'classification', query_value, kwargs)
	@set_check('sinkhole', ['true', 'false'])
	def set_sinkhole(self, query_value, **kwargs):
		return self._router('POST', 'sinkhole', query_value, kwargs)
	@set_check('dynamic', ['true', 'false'])
	def set_dynamic(self, query_value, **kwargs):
		return self._router('POST', 'dynamic', query_value, kwargs)	
	@set_check('ever_compromised', ['true', 'false'])
	def set_ever_compromised(self, query_value, **kwargs):
		return self._router('POST', 'ever_compromised', query_value, kwargs)
	@set_check('watching', ['true', 'false'])
	def set_watching(self, query_value, **kwargs):
		return self._router('POST', 'watching', query_value, kwargs)
	def add_tag(self, query_value, **kwargs):
		if 'tag' not in kwargs:
			raise Exception('Tag is a required field')
		return self._router('POST', 'user/tag/add', query_value, kwargs)
	def remove_tag(self, query_value, **kwargs):
		if 'tag' not in kwargs:
			raise Exception('Tag is a required field')
		return self._router('POST', 'user/tag/remove', query_value, kwargs)
	
	# Helper methods	
	def _router(self, method, query_type, query_value, kwargs=None):
		"""Generic routing method to get the data to and from
		PassiveTotal. All methods should route through this.
		
		@param	method		string	GET or POST
		@param	query_type	string	a valid query endpoint
		@param	query_value	string	item to get data for
		@returns	dict	loaded JSON response
		"""
		call_url = self._endpoint + query_type
		self._logger.debug('Calling: %s' % call_url)
		params = {'api_key': self._api_key, 'query': query_value}
		self._logger.debug('Params: %s' % str(params))
		if method == 'GET':
			response = requests.get(call_url, params=params, verify=False)
		else:
			params.update(kwargs) # update our dict
			response = requests.post(call_url, params=params, verify=False)
		self._logger.debug('Response: %s' % str(response))
		json_response = json.loads(response.content)
		self._logger.debug('Loaded JSON: %s' % json_response)
		return json_response