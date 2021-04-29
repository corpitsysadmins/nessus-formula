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
		status_results = __salt__['nessuscli.run'](nessuscli, 'agent', 'status')
	except RuntimeError as error:
		ret['comment'] = 'Getting the status of the agent failed: ' + str(error)
		return ret
	
	linked = None
	unlink_details = status_results & status_messages['unlinked']
	if len(unlink_details) > 1:
			raise ValueError('The regular expression for "unlinked" yield too many results')
	elif not len(unlink_details):
		LOGGER.debug("The agent doesn't seem to be unlinked")
	else:
		linked = False
	
	if linked is None:
		link_details = status_results & status_messages['linked']
		if len(link_details) > 1:
			raise ValueError('The regular expression for "linked" yield too many results')
		elif not len(link_details):
			LOGGER.debug("The agent doesn't seem to be linked")
		else:
			link_details = link_details[0].groupdict()
			if (link_details['server_host'] == kwargs['host']) and (int(link_details['server_port']) == int(kwargs['port'])):
				linked = True
			else:
				unlink_details = link_details
				linked = False

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
				link_results = __salt__['nessuscli.run_agent_command'](nessuscli, 'link', **kwargs)
			except RuntimeError:
				ret['comment'] = "The unlink command didn't run successfully"
				return ret
			if link_results > status_messages['link_success']:
				link_details = link_results(status_messages['link_success'])
				ret['result'] = True
				ret['comment'] = str(link_details)
				ret['changes'].update({'nessuscli' : {'old' : str(unlink_details), 'new' : str(link_details)}})
			else:	
				ret['result'] = False
				ret['comment'] = 'Unlinking failed: {}'.format(str(link_results))
	
	return ret

def unlinked(name, nessuscli, status_messages):
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
		status_results = __salt__['nessuscli.run_agent_command'](nessuscli, 'status')
	except RuntimeError as error:
		ret['comment'] = 'Getting the status of the agent failed: ' + str(error)
		return ret
	
	if status_results > status_messages['unlinked']:
		linked = False
	elif status_results > status_messages['linked']:
		linked = True
		link_details = status_results(status_messages['linked'])
	else:
		ret['comment'] = 'Getting the status of the agent failed'
		return ret
	
	if linked:
		if __opts__['test']:
			ret['result'] = None
			ret['comment'] = 'The agent would be unlinked from {}:{}'.format(link_details.server_host, link_details.server_port)
		else:
			try:
				unlink_results = __salt__['nessuscli.run_agent_command'](nessuscli, 'unlink')
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
	else:
		ret['result'] = True
		ret['comment'] = 'The agent is already unlinked'
	
	return ret
	