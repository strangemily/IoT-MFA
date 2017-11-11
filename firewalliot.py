#!/usr/bin/python -tt
from netfilter.rule import Rule,Match
from netfilter.table import Table

def allow_rules():
	nattable=Table('nat')
	filtable=Table('filter')

	filtable.set_policy('FORWARD','ACCEPT')

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

	rulehttp=Rule(
		protocol='tcp',
		matches=[Match('tcp', '--dport 80')],
		jump='ACCEPT')
	filtable.append_rule('INPUT',rulehttp)

	rule1=Rule(
		out_interface='eth0',
		jump='MASQUERADE')
	nattable.append_rule('POSTROUTING',rule1)

	rule2=Rule(
		in_interface='eth0',
		out_interface='wlan0',
		jump='ACCEPT',
		matches=[Match('state','--state RELATED,ESTABLISHED')])
	filtable.append_rule('FORWARD',rule2)

	rule3=Rule(
		in_interface='wlan0',
		out_interface='eth0',
		jump='ACCEPT')
	filtable.append_rule('FORWARD',rule3)

	rule4=Rule(
		out_interface='wlan0',
		jump='ACCEPT')
	filtable.append_rule('OUTPUT',rule4)

	rule5=Rule(
		out_interface='eth0',
		jump='ACCEPT')
	filtable.append_rule('OUTPUT',rule5)

	rule6=Rule(
		in_interface='wlan0',
		jump='ACCEPT')
	filtable.append_rule('INPUT',rule6)

def block_rules():
	nattable=Table('nat')
	filtable=Table('filter')

	filtable.set_policy('FORWARD','DROP')

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

	rulehttp=Rule(
		protocol='tcp',
		matches=[Match('tcp', '--dport 80')],
		jump='ACCEPT')
	filtable.append_rule('INPUT',rulehttp)
