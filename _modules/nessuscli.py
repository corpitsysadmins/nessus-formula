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

class LogLine(str):
	'''LogLine abstraction
	Enables the filtering of the line
	'''
	
	def __or__(self, other):
		'''Superset magic
		This basically adds the "filter" function (jinja filter) to the class. The "other" regular expression should use named groups.
		'''
		
		LOGGER.debug('Searching for "%s" in this line: %s', other, self)
		result = re.match(other, self)
		if result is None:
			return None
		else:
			return result.groupdict()


class CommandResults(list):
	'''Command result abstraction
	Groups the log lines from a command run result.
	'''

	def __init__(self, *args, **kwargs):
		'''Initialization magic
		Doesn't do much.
		'''
		
		if (len(args) == 1) and isinstance(args[0], str):
			args = args[0].split('\n')
		
		super().__init__([LogLine(line_) for line_ in args])
		
	def __gt__(self, other):
		'''Superset magic
		This uses the "set logic" interpretation of the ">" operator to check that the "other" string (regular expression) is contained in one of the LogLines.
		'''
		
		for line_ in self:
			result = line_ | other			
			if result is not None:
				return result
		
		return None		
	

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

def run(nessuscli, *params, **kwargs):
	'''Agent command
	Run the agent command and return the log lines.
	'''
	
	if not is_configurable(nessuscli):
		raise RuntimeError('It does not looks like the Nessus agent is installed.')
	
	kwparams = []
	for key, value in kwargs.items():
		kwparams.append('--{}={}'.format(key, value))
	
	LOGGER.debug('Running nessuscli command: %s %s', nessuscli, ' '.join((*params, *kwparams)))
	command_str = __salt__['cmd.run']('{} {}'.format(nessuscli, ' '.join((*params, *kwparams))))
	LOGGER.debug('Run returned: %s', command_str)
	command_result = CommandResults(result_string = command_str)
	
	if not len(command_result):
		raise RuntimeError("The run didn't return a valid line")
	else:
		return command_result
