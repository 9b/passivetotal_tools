<?php

	/**
	 * PHP helper library built on top of the PassiveTotal (www.passivetotal.org)
	 * service API. For updated documentation, head over to www.passivetotal.org/api.
	*/ 
	class PassiveTotal {
	
		/**
		 * Initialize our object with a couple helpers and known-states
		 *
		 * @param	$api_key	string	API key from the PassiveTotal website
		*/
		public function __construct($api_key) {
		    $this->api_key = $api_key;
		    
		    $this->endpoint = 'https://www.passivetotal.org/api/v1/';
			$this->valid_classifications = array('targeted', 'crime', 'multiple', 'benign');
		}
		
		/** 
		 * Generic getter methods that use the router pass-through
		*/
		public function getMetadata($query) {
			return $this->router('GET', 'metadata', $query);
		}
		public function getPassive($query) {
			return $this->router('GET', 'passive', $query);
		}
		public function getSubdomains($query) {
			return $this->router('GET', 'subdomains', $query);
		}
		public function getUnique($query) {
			return $this->router('GET', 'unique', $query);
		}
		public function getClassification($query) {
			return $this->router('GET', 'classification', $query);
		}
		public function getUserTags($query) {
			return $this->router('GET', 'user/tags', $query);
		}
		public function getSinkhole($query) {
			return $this->router('GET', 'sinkhole', $query);
		}
		public function getEverCompromised($query) {
			return $this->router('GET', 'ever_compromised', $query);
		}
		public function getDynamic($query) {
			return $this->router('GET', 'dynamic', $query);
		}
		public function getWatching($query) {
			return $this->router('GET', 'watching', $query);
		}
		
		/** 
		 * Generic setter methods that use the router pass-through
		*/
		public function setClassification($query, array $kwargs) {
			if (!array_key_exists('classification', $kwargs)) {
				throw new Exception('Classification field is required');
			}
			if (!in_array($kwargs['classification'], $this->valid_classifications)) {
				throw new exception('Classification type is not valid');
			}
			return $this->router('POST', 'classification', $query, $kwargs);
		}
		public function setSinkhole($query, array $kwargs) {
			if (!array_key_exists('sinkhole', $kwargs)) {
				throw new Exception('Sinkhole field is required');
			}
			return $this->router('POST', 'sinkhole', $query, $kwargs);
		}
		public function setDynamic($query, array $kwargs) {
			if (!array_key_exists('dynamic', $kwargs)) {
				throw new Exception('Dynamic field is required');
			}
			return $this->router('POST', 'dynamic', $query, $kwargs);
		}
		public function setEverCompromised($query, array $kwargs) {
			if (!array_key_exists('ever_compromised', $kwargs)) {
				throw new Exception('Ever_compromised field is required');
			}
			return $this->router('POST', 'ever_compromised', $query, $kwargs);
		}
		public function setWatching($query, array $kwargs) {
			if (!array_key_exists('watching', $kwargs)) {
				throw new Exception('Watching field is required');
			}
			return $this->router('POST', 'watching', $query, $kwargs);
		}
		public function addUserTag($query, array $kwargs) {
			if (!array_key_exists('tag', $kwargs)) {
				throw new Exception('Tag field is required');
			}
			return $this->router('POST', 'user/tag/add', $query, $kwargs);
		}
		public function removeUserTag($query, array $kwargs) {
			if (!array_key_exists('tag', $kwargs)) {
				throw new Exception('Tag field is required');
			}
			return $this->router('POST', 'user/tag/remove', $query, $kwargs);
		}
		
		/**
		 * Helper function to route user requests to the proper API endpoint
		 * handler. Results will always return JSON.
	     *
	     * @param	$method			string	GET or POST
	     * @param	$query_type		string	Endpoint to query
	     * @param	$query_value	string	Item to query
	     * @param	$kwargs			array	POST variables if needed
	     * @returns JSON encoded data back to the client
		*/
		private function router($method, $query_type, $query_value, array $kwargs=null) {
			$ch = curl_init(); 
		
			$params = array(
				'api_key' => $this->api_key,
				'query' => $query_value
			);
			
			if ($method === 'GET') {
				$query_string = http_build_query($params);
			} else {
				$full_url = $this->endpoint . $query_type;
				$post_fields = array_merge($params, $kwargs);
				$query_string = http_build_query($post_fields);
				curl_setopt($ch,CURLOPT_POST, count($post_fields));
				curl_setopt($ch,CURLOPT_POSTFIELDS, $query_string);	
			}
			
			$full_url = $this->endpoint . $query_type . '?' . $query_string;
			
		    curl_setopt($ch, CURLOPT_URL, $full_url); 
		    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
		    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
		    
		    $output = curl_exec($ch); 
		    curl_close($ch);  
		    
		    return json_decode($output);
		}
	}
?>
