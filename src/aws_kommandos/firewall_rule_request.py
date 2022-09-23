#!/usr/bin/env python3

class FirewallRuleRequest:
    def __init__(self, rule_from_command_line):
        if ':' not in rule_from_command_line:
            raise Exception('Invalid format of the firewall rule. Use --help to see an example.')
        chunks = rule_from_command_line.split(':')
        if len(chunks) != 2 and len(chunks) != 3:
            raise Exception('Invalid number of chunks in the rule. Use --help to see an example.')
        if '/' not in chunks[0]:
            raise Exception('Invalid port specification format. Use --help to see an example.')
        port_specification = chunks[0].split('/')
        try:
            self.port = int(port_specification[0])
        except Exception as ex:
            ex.args = ('Port must be a number. Use --help for more info.',)
            raise
        self.protocol = port_specification[1]
        self.ipv4_address = chunks[1]
        if len(chunks) == 3:
            self.description = chunks[2]
        else:
            self.description = ''

    def __repr__(self):
        return f"[{self.port}/{self.protocol} -> {self.ipv4_address}] - {self.description}"
