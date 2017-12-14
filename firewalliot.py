#!/usr/bin/python -tt
from netfilter.rule import Rule,Match
from netfilter.table import Table

def allow_rules():
	nattable=Table('nat')
	filtable=Table('filter')

	filtable.set_policy('INPUT','ACCEPT')

	nattable.flush_chain('POSTROUTING')
	filtable.flush_chain('FORWARD')
	filtable.flush_chain('OUTPUT')
	filtable.flush_chain('INPUT')

	rulessh=Rule(
		protocol='tcp',
		matches=[Match('tcp', '--dport 22')],
		jump='ACCEPT')
	filtable.append_rule('INPUT',rulessh)

	rulecs=Rule(
		in_interface='wlan0',
		out_interface='eth0',
		protocol='udp',
		matches=[Match('udp', '--dport 32100')],
		jump='ACCEPT')
	filtable.append_rule('FORWARD',rulecs)

	rule0=Rule(
		jump='ACCEPT',
		matches=[Match('state','--state RELATED,ESTABLISHED')])
	filtable.append_rule('INPUT',rule0)

	rule1=Rule(
		out_interface='eth0',
		jump='MASQUERADE')
	nattable.append_rule('POSTROUTING',rule1)

	rule2=Rule(
		in_interface='wlan0',
		out_interface='eth0',
		jump='ACCEPT')
	filtable.append_rule('FORWARD',rule2)

	rule3=Rule(
		out_interface='wlan0',
		jump='ACCEPT')
	filtable.append_rule('OUTPUT',rule3)

	rule4=Rule(
		out_interface='eth0',
		jump='ACCEPT')
	filtable.append_rule('OUTPUT',rule4)

	rule5=Rule(
		in_interface='wlan0',
		jump='ACCEPT')
	filtable.append_rule('INPUT',rule5)

	rule6=Rule(
		in_interface='lo',
		jump='ACCEPT')
	filtable.append_rule('INPUT',rule6)

	rule7=Rule(
		out_interface='lo',
		jump='ACCEPT')
	filtable.append_rule('OUTPUT',rule7)

	filtable.set_policy('FORWARD','DROP')
	filtable.set_policy('INPUT','DROP')
	filtable.set_policy('OUTPUT','DROP')

def block_rules():
	nattable=Table('nat')
	filtable=Table('filter')

	filtable.set_policy('INPUT','ACCEPT')

	nattable.flush_chain('POSTROUTING')
	filtable.flush_chain('FORWARD')
	filtable.flush_chain('OUTPUT')
	filtable.flush_chain('INPUT')
	#nattable.delete_chain()

	rulessh=Rule(
		protocol='tcp',
		matches=[Match('tcp', '--dport 22')],
		jump='ACCEPT')
	filtable.append_rule('INPUT',rulessh)

	rulecs=Rule(
		in_interface='wlan0',
		out_interface='eth0',
		protocol='udp',
		matches=[Match('udp', '--dport 32100')],
		jump='ACCEPT')
	filtable.append_rule('FORWARD',rulecs)

	rulefreturn=Rule(
		in_interface='eth0',
		out_interface='wlan0',
		jump='ACCEPT',
		matches=[Match('state','--state RELATED,ESTABLISHED')])
	filtable.append_rule('FORWARD',rulefreturn)

	rule0=Rule(
		jump='ACCEPT',
		matches=[Match('state','--state RELATED,ESTABLISHED')])
	filtable.append_rule('INPUT',rule0)

	rule1=Rule(
		out_interface='eth0',
		jump='MASQUERADE')
	nattable.append_rule('POSTROUTING',rule1)

	rule2=Rule(
		out_interface='wlan0',
		jump='ACCEPT')
	filtable.append_rule('OUTPUT',rule2)

	rule3=Rule(
		out_interface='eth0',
		jump='ACCEPT')
	filtable.append_rule('OUTPUT',rule3)

	rule4=Rule(
		in_interface='wlan0',
		jump='ACCEPT')
	filtable.append_rule('INPUT',rule4)

	rule5=Rule(
		in_interface='lo',
		jump='ACCEPT')
	filtable.append_rule('INPUT',rule5)

	rule6=Rule(
		out_interface='lo',
		jump='ACCEPT')
	filtable.append_rule('OUTPUT',rule6)

	filtable.set_policy('FORWARD','DROP')
	filtable.set_policy('INPUT','DROP')
	filtable.set_policy('OUTPUT','DROP')
