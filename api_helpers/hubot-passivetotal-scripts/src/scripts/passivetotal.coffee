# Description:
#   PassiveTotal
#
# Dependencies:
#   None
#
# Configuration:
#   PASSIVETOTAL_KEY - Sign up at https://www.passivetotal.org/register
#
# Commands:
#		hubot pt current api key - Get the current API key value
#		hubot	pt set api key <value> - Set the API key
#		hubot	pt classification for <value> - Get the classification for the value
#		hubot	pt classify <value> as <targeted|crime|multiple|benign> - Classify the value
#		hubot	pt is <value> <a sinkhole|sinkholed> - Determine if an IP is a sinkhole
#		hubot	pt is <value> <dyn|dynamic|a dynamic provider|a dyn provider> - Determine if domain is dynamic DNS
#		hubot	pt has <value> <ever been compromised|been compromised> - Determine if value has been compromised
#		hubot	pt show me tags for <value> - Get the tags for the value
#		hubot	pt tag <value> <with|as> <tag> - Add tag value
#		hubot	pt remove <tag> from <value> - Remove add value
#		hubot	pt show me metadata for <value> - Get metadata
#		hubot	pt show me passive for <value - Get passive results
#		hubot	pt show me unique for <value> - Get unique resolves
#
# Author:
#		Brandon Dixon <brandon@passivetotal.org>

PASSIVETOTAL_KEY = process.env.PASSIVETOTAL_KEY
PASSIVETOTAL_API = "https://www.passivetotal.org"
PT_METADATA_URL = PASSIVETOTAL_API + "/api/v1/metadata"
PT_PASSIVE_URL = PASSIVETOTAL_API + "/api/v1/passive"
PT_SUBDOMAIN_URL = PASSIVETOTAL_API + "/api/v1/subdomain"
PT_UNIQUE_URL = PASSIVETOTAL_API + "/api/v1/unique"
PT_CLASSIFICATION_URL = PASSIVETOTAL_API + "/api/v1/classification"
PT_TAGS_URL = PASSIVETOTAL_API + "/api/v1/user/tags"
PT_TAG_ADD_URL = PASSIVETOTAL_API + "/api/v1/user/tag/add"
PT_TAG_REMOVE_URL = PASSIVETOTAL_API + "/api/v1/user/tag/remove"
PT_SINKHOLE_URL = PASSIVETOTAL_API + "/api/v1/sinkhole"
PT_DYNAMIC_URL = PASSIVETOTAL_API + "/api/v1/dynamic"
PT_EVER_COMPROMISED_URL = PASSIVETOTAL_API + "/api/v1/ever_compromised"

positive_findings = ['Appears so!', 'Last I checked', 'Yes', 'Indeed', 'Yeah buddy!']
negative_findings = ['No', 'Nope', 'Not from what I can see', 'Negative', 'Nah']
no_findings = ['Hmm, nothing found!', 'Ive got nothing', 'No useful results, sorry']
success_answers = ['Success!', 'All done', 'You got it']

validate = (response, body) ->
	if response.statusCode is 200
		json = JSON.parse(body)
		if json.success
			return {
				success: true,
				content: json
			}
		else
			return {
				success: false,
				msg: "Hmm, ran into some trouble. Server says #{json.error}"
			}
	else 
		return {
			success: false,
			msg: "Server is having issues, try again later"
		}

module.exports = (robot) ->

	robot.hear /pt current api key/i, (msg) ->
		msg.reply "API key set to #{PASSIVETOTAL_KEY}"
		
	robot.hear /pt set api key to (.*)/i, (msg) ->
		PASSIVETOTAL_KEY = msg.match[1].toLowerCase()
		msg.reply msg.random success_answers

	robot.hear /pt classify (.*) as (targeted|crime|multiple|benign)/i, (msg) ->
		value = msg.match[1].toLowerCase().replace('http://', '')
		classification = msg.match[2].toLowerCase()
		data = "api_key=#{encodeURIComponent PASSIVETOTAL_KEY}&query=#{encodeURIComponent value}&classification=#{encodeURIComponent classification}"
		
		robot.http(PT_CLASSIFICATION_URL)
			.post(data) (err, res, body) ->
				response = ""
				
				validation = validate(res, body)
				if validation['success']
					response += msg.random success_answers
				else
					response += validation['msg']
				
				msg.send response
				
	robot.hear /pt classification for (.*)(\\?)?/i, (msg) ->
		re = new RegExp('(\\?|\\!)', 'g');
		value = msg.match[1].toLowerCase().replace('http://', '').replace(re, '')
		data = "?api_key=#{encodeURIComponent PASSIVETOTAL_KEY}&query=#{encodeURIComponent value}"
		robot.http(PT_CLASSIFICATION_URL + data)
			.get(data) (err, res, body) ->
				response = ""
				validation = validate(res, body)
				if validation['success']
					json = validation['content']
					results = json.results
					if results.classification != ''
						response += "#{json.raw_query} is classified as #{results.classification}"
					else
						response += "No classification has been set yet!"
				else
					response += validation['msg']
				
				msg.send response
				
	robot.hear /pt is (.*) (a sinkhole|sinkholed)/i, (msg) ->
		value = msg.match[1].toLowerCase().replace('http://', '')
		data = "?api_key=#{encodeURIComponent PASSIVETOTAL_KEY}&query=#{encodeURIComponent value}"
		
		robot.http(PT_SINKHOLE_URL + data)
			.get(data) (err, res, body) ->
				response = ""
				
				validation = validate(res, body)
				if validation['success']
					json = validation['content']
					results = json.results
					
					if results.sinkhole
						response += msg.random positive_findings
					else
						response += msg.random negative_findings
						
				else
					response += validation['msg']
				
				msg.send response
				
	robot.hear /pt is (.*) (dyn|dynamic|a dynamic provider|a dyn provider)/i, (msg) ->
		value = msg.match[1].toLowerCase().replace('http://', '')
		data = "?api_key=#{encodeURIComponent PASSIVETOTAL_KEY}&query=#{encodeURIComponent value}"
		
		robot.http(PT_DYNAMIC_URL + data)
			.get(data) (err, res, body) ->
				response = ""
				
				validation = validate(res, body)
				if validation['success']
					json = validation['content']
					results = json.results
					
					if results.dynamic
						response += msg.random positive_findings
					else
						response += msg.random negative_findings
						
				else
					response += validation['msg']
				
				msg.send response
				
	robot.hear /pt has (.*) (ever been compromised|been compromised)/i, (msg) ->
		value = msg.match[1].toLowerCase().replace('http://', '')
		data = "?api_key=#{encodeURIComponent PASSIVETOTAL_KEY}&query=#{encodeURIComponent value}"
		
		robot.http(PT_EVER_COMPROMISED_URL + data)
			.get(data) (err, res, body) ->
				response = ""
				
				validation = validate(res, body)
				if validation['success']
					json = validation['content']
					results = json.results
					
					if results.ever_compromised
						response += msg.random positive_findings
					else
						response += msg.random negative_findings
						
				else
					response += validation['msg']
				
				msg.send response
				
	robot.hear /pt show me tags for (.*)/i, (msg) ->
		value = msg.match[1].toLowerCase().replace('http://', '')
		data = "?api_key=#{encodeURIComponent PASSIVETOTAL_KEY}&query=#{encodeURIComponent value}"
		
		robot.http(PT_TAGS_URL + data)
			.get(data) (err, res, body) ->
				response = ""
				
				validation = validate(res, body)
				if validation['success']
					json = validation['content']
					results = json.results
					
					if results.tags.length > 0
						if results.tags.length == 1
							response += "I found #{results.tags.length} tag:\n"
						else
							response += "I found #{results.tags.length} tags:\n"
							
						response += results.tags.join(', ')
					else
						response += msg.random no_findings
						
				else
					response += validation['msg']
				
				msg.send response
	
	robot.hear /pt tag (.*) (with|as) (.*)/i, (msg) ->
		msg.reply msg.match
		value = msg.match[1].toLowerCase().replace('http://', '')
		tag = msg.match[3]
		data = "api_key=#{encodeURIComponent PASSIVETOTAL_KEY}&query=#{encodeURIComponent value}&tag=#{encodeURIComponent tag}"
		
		robot.http(PT_TAG_ADD_URL)
			.post(data) (err, res, body) ->
				response = ""
				
				validation = validate(res, body)
				if validation['success']
					response += msg.random success_answers
				else
					response += validation['msg']
				
				msg.send response
				
	robot.hear /pt remove (.*) from (.*)/i, (msg) ->
		msg.reply msg.match
		tag = msg.match[1]
		value = msg.match[2].toLowerCase().replace('http://', '')
		data = "api_key=#{encodeURIComponent PASSIVETOTAL_KEY}&query=#{encodeURIComponent value}&tag=#{encodeURIComponent tag}"
		
		robot.http(PT_TAG_REMOVE_URL)
			.post(data) (err, res, body) ->
				response = ""
				
				validation = validate(res, body)
				if validation['success']
					response += msg.random success_answers
				else
					response += validation['msg']
				
				msg.send response
		
	robot.hear /pt show me metadata for (.*)/i, (msg) ->
		value = msg.match[1].toLowerCase()
		data = "?api_key=#{encodeURIComponent PASSIVETOTAL_KEY}&query=#{encodeURIComponent value}"
		robot.http(PT_METADATA_URL + data)
			.get() (err, res, body) ->
				response = ""
				
				validation = validate(res, body)
				if validation['success']
					json = validation['content']
					results = json.results
					
					response += "Here's what I know:\n"
					if json.results.type is "domain"
						response += "*Base domain:* #{results.primaryDomain}\n"
						response += "*TLD:* #{results.tld}\n"
						response += "*Dynamic:* #{results.dynamic}\n"
					else
						response += "*Netblock:* #{results.network}\n"

					response += "*Ever Compromised:* #{results.ever_compromised}\n"
				else
					response += validation['msg']
					
				msg.send response	
				
	robot.hear /pt show me passive for (.*)/i, (msg) ->
		value = msg.match[1].toLowerCase()
		data = "?api_key=#{encodeURIComponent PASSIVETOTAL_KEY}&query=#{encodeURIComponent value}"
		robot.http(PT_PASSIVE_URL + data)
			.get() (err, res, body) ->
				response = ""
				
				validation = validate(res, body)
				if validation['success']
					json = validation['content']
					results = json.results
					
					if json.result_count > 0
						response += "Here's a snippet of results:\n"
						response += "*Resolve count:* " + json.result_count + "\n"
						response += "*First seen:* " + results.first_seen + "\n"
						response += "*Last seen:* " + results.last_seen + "\n"
						response += "*Unique resolves:* " + Object.keys(results.unique_resolutions).length + "\n"
						response += "*Used sources:* " + results.sources_used.join(', ') + "\n"
						for record, i in results.records when i < 5
							sources = record.source.join(', ')
							response += "=> #{record.firstSeen}\t#{record.lastSeen}\t#{record.resolve}\n"

					else
						response += msg.random no_findings
	
				else
					response += validation['msg']
					
				msg.send response	
				
	robot.hear /pt show me unique for (.*)/i, (msg) ->
		value = msg.match[1].toLowerCase()
		data = "?api_key=#{encodeURIComponent PASSIVETOTAL_KEY}&query=#{encodeURIComponent value}"
		robot.http(PT_UNIQUE_URL + data)
			.get() (err, res, body) ->
				response = ""
				
				validation = validate(res, body)
				if validation['success']
					json = validation['content']
					results = json.results

					if json.result_count > 0
						response += "Here's what I know:\n"
						for key, value of results
							response += "=> #{key}\n"
					else
						response += msg.random no_findings
				else
					response += validation['msg']
					
				msg.send response	

