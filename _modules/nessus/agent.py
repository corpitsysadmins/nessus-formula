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

class LogLine:
	'''LogLine abstraction
	Gets the log text line and parses it as much as possible.
	'''
	
	BASIC_RE = '^\s*\[(?P<_first>.+?)]\s*\[(?P<_second>.+?)]\s*(?P<_message>.*?)\s*$'
	MESSAGE_RES = (
		'^\s*(?P<linked_str>Linked to:\s*(?P<server_host>\S+):(?P<server_port>\d{1,5}))\s*$',
	)
	_valid = None
	
	def __init__(self, log_line, auto_parse = False):
		'''Initialization magic
		Does the basic line parsing and triggers the message parsing if enabled (the default).
		'''
		
		LOGGER.debug('Creating LogLine from: %s', log_line)
		basic_log = re.match(self.BASIC_RE, log_line)
		
		if basic_log is None:
			raise ValueError('Not a valid log string: {}'.format(log_line))
			
		for name, value in basic_log.groupdict().items():
			if (value is not None) and len(value.strip()):
				setattr(self, name, value)
			
		if auto_parse:
			bool(self)
	
	def __bool__(self):
		'''Boolean magic
		Returns the parsing status of the message. Triggers the parsing is not done yet.
		'''
	
		if self._valid is None:
			parsed = self.parse_message(self._message)
			if len(parsed):
				self._valid = True
				for name, value in parsed.items():
					if (value is not None) and len(value.strip()):
						setattr(self, name, value)
			else:
				self._valid = False
			
		return self._valid
	
	def __gt__(self, other):
		'''Superset magic
		This uses the "set logic" interpretation of the ">" operator to check that the "other" string (regular expression) is contained in the message.
		'''
		
		LOGGER.debug('Searching for "%s" in this line: %s', other, self)
		search = re.search(str(other), self._message, re.I)
		if search is None:
			return False
		else:
			return True
		
		
	def __getattr__(self, name):
		'''Attribute magic
		Trigger the message parsing, for the non-autoparse option.
		'''
		
		if self._valid is None:
			bool(self)
			return getattr(self, name)
		
		raise AttributeError('Attribute not found: {}'.format(name))
	
	def __str__(self):
		'''String magic
		Returns the unparsed message.
		'''
		
		return self._message
	
	def parse_message(cls, message):
		'''Parse the message
		Use all available regular expressions to try to parse the message.
		'''
		
		result = {}
		LOGGER.debug('Parsing message: %s', message)
		for re_ in cls.MESSAGE_RES:
			match = re.match(re_, message)
			if match is not None:
				result = match.groupdict()
				break
		
		return result


class CommandResults(list):
	'''Command result abstraction
	Groups the log lines from a command run result.
	'''

	def __init__(self, *args, **kwargs):
		'''Initialization magic
		Doesn't do much.
		'''
		
		super().__init__(*args, **kwargs)
		
	def __call__(self, other):
		'''Call magic
		Search for a LogLine that matches "other".
		'''
		
		LOGGER.debug('Looking for a LogLine like: %s', other)
		for result in self:
			if result > other:
				LOGGER.debug('Found it: %s', result)
				return result
		LOGGER.debug("Couldn't find '%s' in %s", other, self)
		return None
		
	def __gt__(self, other):
		'''Superset magic
		This uses the "set logic" interpretation of the ">" operator to check that the "other" string (regular expression) is contained in one of the LogLines.
		'''
		
		if self(other) is None:
			return False
		else:
			return True
	
	def __str__(self):
		'''String magic
		Returns some debuggable representation.
		'''
		
		return ' | '.join([str(value) for value in self])
	

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
	command_result = CommandResults()
	for line in command_str.split('\n'):
		try:
			command_result.append(LogLine(line))
		except ValueError:
			LOGGER.warning('Not a valid log line: %s', line)
	
	if not len(command_result):
		raise RuntimeError("The run didn't return a valid line")
	else:
		return command_result
