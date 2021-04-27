#! python
'''Nessus agent execution module.
This module implements the execution actions related to the Nessus agent.

Version: 0.0.3

TODO:
- everything

Refs:
'''

import logging

import re

LOGGER = logging.getLogger(__name__)

class CommandResults(dict):
	'''Command result abstraction
	Groups the log lines from a command run result.
	'''

	def __init__(self, *args, result_string = None, **kwargs):
		'''Initialization magic
		Doesn't do much.
		'''
		
		super().__init__(*args, **kwargs)
		self.update(self._parse_result(result_string))
		
	def __call__(self, search_re):
		'''Call magic
		Search for a line with certain regular expression.
		'''
		
		LOGGER.debug('Looking for a LogLine like: %s', other)
		for key_ in self:
			if re.match(search_re, key_):
				return self[key_]
		LOGGER.debug("Couldn't find '%s' in %s", other, self)
		raise KeyError('The expression did not yield any key: {}'.format(search_re))
		
	def _parse_result(self, result_string):
		
		result = {}
		
		if result_string is None:
			return result
		
		for line in result_string.split('\n'):
			split_ = line.split(':', maxsplit = 1)
			if len(split_) == 2:
				result[split_[0]] = split_[1]
			else:
				LOGGER.warning('Not a valid log line: %s', line)				
		
		return result
	

def is_configurable(nessuscli):
	'''Check for nessuscli
	Checks if the binary exists and is usable. This binary is used to configure the Nessus agent.
	'''
	
	try:
		stats = __salt__['file.stats'](nessuscli)
		LOGGER.debug('The stats for %s are: %s', nessuscli, stats)
		if (stats['type'] not in ['file']) or not (int(stats['mode'], 8) & 64):
			raise Exception()
	except Exception:
		return False
	else:
		return True

def run_agent_command(nessuscli, command, *params, **kwargs):
	'''Agent command
	Run the agent command and return the log lines.
	'''
	
	kwparams = []
	for key, value in kwargs.items():
		kwparams.append('--{}={}'.format(key, value))
	
	if not is_configurable(nessuscli):
		raise RuntimeError('It does not looks like the Nessus agent is installed.')
	
	LOGGER.debug('Running agent state command: %s agent %s', nessuscli, ' '.join((command, *params, *kwparams)))
	command_str = __salt__['cmd.run']('{} agent {}'.format(nessuscli, ' '.join((command, *params, *kwparams))))
	command_result = CommandResults(result_string = command_str)
	
	if not len(command_result):
		raise RuntimeError("The run didn't return a valid line")
	else:
		return command_result
