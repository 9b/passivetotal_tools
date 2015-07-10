#!/usr/bin/env python

"""PassiveTotal Command Line Interface

Copyright (c) 2015, PassiveTotal LLC.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Usage:
	passivetotal_cli.py metadata <indicator> [--raw]
  passivetotal_cli.py passive <indicator> [--raw]
  passivetotal_cli.py subdomains <indicator> [--raw]
  passivetotal_cli.py unique <indicator> [--raw]
  passivetotal_cli.py classify <indicator> (targeted|crime|multiple|benign) [--bulk]
  passivetotal_cli.py (add|remove) tag <indicator> <tag> [--bulk]
  passivetotal_cli.py (-h | --help)
  passivetotal_cli.py --version

Options:
  -h --help     Show this screen.
  --version     Show version.
  --raw         Dump the results in raw JSON.
  --bulk        Read values from a file instead of the CLI.

"""

import os
import sys
from docopt import docopt
from IPy import IP
from passivetotal import PassiveTotal

API_KEY = '-YOUR-API-KEY-'

if __name__ == '__main__':
	arguments = docopt(__doc__, version='PassiveTotal 1.0')
	
	pt = PassiveTotal(API_KEY)
	pt.logger = 'INFO'
	
	if arguments['metadata']:
		response = pt.get_metadata(arguments['<indicator>'])
		if response['success']:
			if arguments['--raw']:
				print response
			else:
				print "[=] Query:", response['raw_query']
				type = response['results']['type']
				if type == 'domain':
					print "[*] Primary Domain:", response['results']['primaryDomain']
					print "[*] TLD:", response['results']['tld']
					print "[*] Dynamic DNS?:", response['results']['dynamic']
				else:
					print "[*] Country:", response['results']['country']
					print "[*] Network:", response['results']['network']
					print "[*] AS Number:", response['results']['asn']
					print "[*] AS Name:", response['results']['as_name']
					print "[*] Sinkhole?:", response['results']['sinkhole']
				
				print "[*] Ever Compromised?:", response['results']['ever_compromised']
				print "[*] Tags:", ', '.join([ str(x) for x in response['results']['tags'] ])
				
		else:
			print "[!] Error when getting metadata for %s: %s" % (arguments['<indicator>'], response['error'])
	
	if arguments['passive']:
		response = pt.get_passive(arguments['<indicator>'])
		if response['success']:
			if arguments['--raw']:
				print response
			else:
				print "[=] Query:", response['raw_query']
				print "[*] First Seen:", response['results']['first_seen']
				print "[*] Last Seen:", response['results']['last_seen']
				print "[*] Resolve Count: ", response['result_count']
				print "[*] Resolutions"
				response = response['results']
				for resolve in response['records']:
					print "=>", resolve['resolve'], "\t", resolve['firstSeen'], "\t", resolve['lastSeen'], "\t", ', '.join([ str(x) for x in resolve['source'] ])
		else:
			print "[!] Error when getting passive for %s: %s" % (arguments['<indicator>'], response['error'])
			
	if arguments['subdomains']:
		if not arguments['<indicator>'].startswith('*.'):
			arguments['<indicator>'] = '*.' + arguments['<indicator>']
		response = pt.get_subdomains(arguments['<indicator>'])
		if response['success']:
			if arguments['--raw']:
				print response
			else:
				print "[=] Query:", response['raw_query']
				response = response['results']
				print "[*] First Seen:", response['first_seen']
				print "[*] Last Seen:", response['last_seen']
				print "[*] Subdomains: ", ', '.join(response['subdomains'].keys())
				for subdomain, details in response['subdomains'].iteritems():
					print "[=]", subdomain, "Resolutions"
					for resolve in details['records']:
						print "=>", resolve['resolve'], "\t", resolve['firstSeen'], "\t", resolve['lastSeen'], "\t", ', '.join([ str(x) for x in resolve['source'] ])
		else:
			print "[!] Error when getting subdomain details for %s: %s" % (arguments['<indicator>'], response['error'])
			
	if arguments['unique']:
		response = pt.get_unique(arguments['<indicator>'])
		if response['success']:
			if arguments['--raw']:
				print response
			else:
				print "[=] Query:", response['raw_query']
				print "[*] Resolutions"
				response = response['results']
				for item, count in response.iteritems():
					print "=>", item, "\t[%d]" % count
		else:
			print "[!] Error when getting unique resolutions for %s: %s" % (arguments['<indicator>'], response['error'])
			
	if arguments['classify']:
		if not arguments['--bulk']:
			if arguments['targeted']:
				response = pt.set_classification(arguments['<indicator>'], classification='targeted')
			elif arguments['crime']:
				response = pt.set_classification(arguments['<indicator>'], classification='crime')
			elif arguments['multiple']:
				response = pt.set_classification(arguments['<indicator>'], classification='multiple')
			else:
				response = pt.set_classification(arguments['<indicator>'], classification='benign')
				
			if response['success']:
				print "[*] Successfully classified %s" % arguments['<indicator>']
			else:
				print "[!] Error when trying to classify %s: %s" % (arguments['<indicator>'], response['error'])
		else:
			if os.path.exists(arguments['<indicator>']):
				items = [ x.strip() for x in open(arguments['<indicator>'], 'r').readlines() ]
				for item in items:
					if arguments['targeted']:
						response = pt.set_classification(item, classification='targeted')
					elif arguments['crime']:
						response = pt.set_classification(item, classification='crime')
					elif arguments['multiple']:
						response = pt.set_classification(item, classification='multiple')
					else:
						response = pt.set_classification(item, classification='benign')

					if response['success']:
						print "[*] Successfully classified %s" % item
					else:
						print "[!] Error when trying to classify %s: %s" % (item, response['error'])
			
	if arguments['tag']:
		if not arguments['--bulk']:
			if arguments['add']:
				response = pt.add_tag(arguments['<indicator>'], tag=arguments['<tag>'])
			else:
				response = pt.remove_tag(arguments['<indicator>'], tag=arguments['<tag>'])
			
			if response['success']:
				if arguments['add']:
					print "[*] Successfully tagged %s with %s" % (arguments['<indicator>'], arguments['<tag>'])
				else:
					print "[*] Successfully untagged %s from %s" % (arguments['<tag>'], arguments['<indicator>'])
			else:
				print "[!] Error when trying to tag %s: %s" % (arguments['<indicator>'], response['error'])
				
		else:
			if os.path.exists(arguments['<indicator>']):
				items = [ x.strip() for x in open(arguments['<indicator>'], 'r').readlines() ]
				for item in items:
					if arguments['add']:
						response = pt.add_tag(item, arguments['<tag>'])
					else:
						response = pt.remove_tag(item, arguments['<tag>'])
					
					if response['success']:
						print "[*] Successfully tagged %s with %s" % (item, arguments['<tag>'])
					else:
						print "[!] Error when trying to tag %s: %s" % (item, response['error'])

