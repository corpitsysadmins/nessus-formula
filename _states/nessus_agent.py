#! python
'''Nessus agent module.
This module implements the states related to the Nessus agent.

Version: 0.2.4

TODO:
- everything

Refs:
'''

import logging

import re

LOGGER = logging.getLogger(__name__)

def _agent_status(nessuscli, status_messages, expected_host = None, expected_port = None):
	'''Agent status command
	Run the agent status command and return the parsed status.
	'''
	
	status_results = __salt__['nessuscli.run'](nessuscli, 'agent', 'status')
	
	linked, link_details, unlink_details = None, None, None
	
	unlink_details = status_results & status_messages['unlinked']
	if len(unlink_details) > 1:
			raise ValueError('The regular expression for "unlinked" yield too many results')
	elif not len(unlink_details):
		LOGGER.debug("The agent doesn't seem to be unlinked")
	else:
		unlink_details = unlink_details[0]
		linked = False
	
	if linked is None:
		link_details = status_results & status_messages['linked']
		if len(link_details) > 1:
			raise ValueError('The regular expression for "linked" yield too many results')
		elif not len(link_details):
			LOGGER.debug("The agent doesn't seem to be linked")
		else:
			link_details = link_details[0]
			linked = True
			link_details_groups = (link_details | status_messages['linked']).groupdict()
			if (link_details_groups['server_host'] != expected_host) or (int(link_details_groups['server_port']) != int(expected_port)):
				unlink_details = link_details
	
	return linked, link_details, unlink_details

def linked(name, nessuscli, status_messages, host, port, key, **kwargs):
	'''Link agent
	Link and already installed Nessus/Tenable agent to a server.
	'''
	
	ret	=	{
		'name'		: name,
		'result'	: False,
		'changes'	: {},
		'comment'	: '',
	}
	kwargs.update({'host' : host, 'port' : port, 'key' : key})
	
	if not __salt__['nessuscli.is_configurable'](nessuscli):
		if __opts__['test']:
			ret['result'] = None
			ret['comment'] = "The Nessus agent doesn't seem to be installed; if installed in this state run, it would have been linked."
		else:
			ret['result'] = False
			ret['comment'] = "The Nessus agent doesn't seem to be installed. The linking procedure can't be performed."
		return ret
	
	try:
		linked, unlink_details, link_details = _agent_status(nessuscli, status_messages, kwargs['host'], kwargs['port'])
	except RuntimeError as error:
		ret['comment'] = 'Getting the status of the agent failed: ' + str(error)
		return ret
	else:
		LOGGER.debug('Current agent status is: %s | %s | %s', linked, unlink_details, link_details)

	if linked is None:
		ret['comment'] = 'Getting the status of the agent failed'
		return ret
	
	if linked:
		ret['result'] = True
		ret['comment'] = 'The agent is already linked to {}:{}'.format(link_details['server_host'], link_details['server_port'])
	else:
		if __opts__['test']:
			ret['result'] = None
			ret['comment'] = 'The agent would be linked to {host}:{port}'.format(**kwargs)
			ret['changes'].update({'nessuscli' : {'old' : str(unlink_details), 'new' : 'Linked to: {host}:{port}'.format(**kwargs)}})
		else:
			try:
				linking_results = __salt__['nessuscli.run'](nessuscli, 'agent', 'link', **kwargs)
			except RuntimeError:
				ret['comment'] = "The link command didn't run successfully"
				return ret
			
			link_details = linking_results & status_messages['link_success']
			if len(link_details) > 1:
				raise ValueError('The regular expression for "link_success" yield too many results')
			elif not len(link_details):
				LOGGER.debug("The agent link didn't return an expected message")
				ret['result'] = False
				ret['comment'] = 'Linking failed: {}'.format(str(linking_results))
			else:
				ret['result'] = True
				ret['comment'] = link_details[0]
				ret['changes'].update({'nessuscli' : {'old' : str(unlink_details), 'new' : str(link_details[0])}})	
	
	return ret

def unlinked(name, nessuscli, status_messages, *args, **kwargs):
	'''Unlink agent
	Unlink an already configured agent from the Nessus/Tenable server/cloud.
	'''
	
	ret	=	{
		'name'		: name,
		'result'	: False,
		'changes'	: {},
		'comment'	: '',
	}
	
	if not __salt__['nessuscli.is_configurable'](nessuscli):
		ret['result'] = True
		ret['comment'] = "The Nessus agent doesn't seems to be installed; if installed in this state run, it would have been unlinked"
		return ret
	
	try:
		linked, link_details, unlink_details = _agent_status(nessuscli, status_messages)
	except RuntimeError as error:
		ret['comment'] = 'Getting the status of the agent failed: ' + str(error)
		return ret
	else:
		LOGGER.debug('Current agent status is: %s | %s | %s', linked, link_details, unlink_details)
	
	if linked is None:
		ret['comment'] = 'Getting the status of the agent failed'
		return ret
	
	if not linked:
		ret['result'] = True
		ret['comment'] = 'The agent is already unlinked'
	else:
		if __opts__['test']:
			ret['result'] = None
			ret['comment'] = 'The agent would be unlinked from {}:{}'.format(link_details['server_host'], link_details['server_port'])
		else:
			try:
				unlinking_results = __salt__['nessuscli.run'](nessuscli, 'agent', 'unlink')
			except RuntimeError:
				ret['comment'] = "The unlink command didn't run successfully"
				return ret
			if unlink_results > status_messages['unlink_success']:
				unlink_details = unlink_results(status_messages['unlink_success'])
				ret['result'] = True
				ret['comment'] = str(unlink_details)
				ret['changes'].update({'nessuscli' : {'old' : str(link_details), 'new' : str(unlink_details)}})
			else:	
				ret['result'] = False
				ret['comment'] = 'Unlinking failed: {}'.format(str(unlink_results))
	
	return ret
	