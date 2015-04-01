<?php 
	require_once('passivetotal.php');
	
	# create a new instance
	$pt = new PassiveTotal('-YOUR API KEY HERE-');
	
	# get pdns information
	echo $pt->getPassive('www.passivetotal.org');
	
	# set classification
	echo $pt->setClassification('www.passivetotal.org', array('classification' => 'benign'));
	
	# set a tag
	echo $pt->addUserTag('www.passivetotal.org', array('tag' => 'security'));
 ?>
