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
	
	def __matmul__(self, other):
		'''Superset magic
		Check if the "other" regular expression matches this string.
		'''
		
# 		LOGGER.debug('Checking if regular expression matches')
		if (self | other) is None:
			return False
		else:
			return True
	
	def __or__(self, other):
		'''Superset magic
		This basically adds the "filter" function (jinja filter) to the class. The "other" regular expression should use named groups.
		'''
		
# 		LOGGER.debug('Trying to match "%s" in this line: %s', other, self)
		result = re.match(other, self)
		if result is None:
			return None
		else:
			ret = FilteredLogLine(self)
			ret._parsed = result
			return ret


class FilteredLogLine(str):
	'''Filtered LogLine abstraction
	Result of a line filtering. Expected to include a "._parse" attributing holding the re.Match object.
	'''
	
	def groupdict(self):
		'''Parsed results
		Get the groups from the match object.
		'''
		
		return self._parsed.groupdict()


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
		
	def __and__(self, other):
		'''Superset magic
		This uses the "set logic" interpretation of the "&" operator to check that the "other" string (regular expression) to create a list with the contained LogLines that matches the regular expression.
		'''
		
		result = []
		for line_ in self:
			filtered_line = line_ | other			
			if filtered_line is not None:
				result.append(filtered_line)
		
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

def run(nessuscli, *params, **kwargs):
	'''Run nessuscli command
	Run the nessuscli command and return the log lines.
	'''
	
	if not is_configurable(nessuscli):
		raise RuntimeError('It does not looks like the Nessus agent is installed.')
	
	kwparams = ['--{}={}'.format(key, value) for key, value in kwargs.items() if key[0] != '_']
	
	LOGGER.debug('Running nessuscli command: %s %s', nessuscli, ' '.join((*params, *kwparams)))
	command_str = __salt__['cmd.run']('{} {}'.format(nessuscli, ' '.join((*params, *kwparams))))
	return CommandResults(command_str)
