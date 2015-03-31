#!/usr/bin/env python

from passivetotal import PassiveTotal
		
# create a new instance
pt = PassiveTotal('-YOUR API KEY HERE-')

# set our logging
pt.logger = 'DEBUG'

# get pdns information
print pt.get_passive('www.passivetotal.org')

# set classification
print pt.set_classification('www.passivetotal.org', classification='benign')

# set a tag
print pt.add_tag('www.passivetotal.org', tag='security')


