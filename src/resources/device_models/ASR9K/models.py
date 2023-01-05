from src.resources import *
import re


class Interface(Resource):

    oper_cmd = "show interfaces"
    oper_cmd_filter = lambda self, name: f'sho interfaces {name}'
    oper_cmd_brief = "show interfaces description"
    config_cmd = "show running interfaces"
    config_cmd_filter = lambda self, name: f'sho running interfaces {name}'

    @register('postprocess')
    def blah(self, data):
        if 'name' in data.keys():
            data['name'] = self.device.lengthen_ifname(data['name'])
        if 'state' in data.keys():
            if re.match("up", data['state'], re.IGNORECASE):
                data['state'] = "up"
            elif re.match("admin.*down", data['state'], re.IGNORECASE):
                data['state'] = "admin-down"
            elif re.match("down", data['state'], re.IGNORECASE):
                data['state'] = "down"
            else:
                raise ValueError('Cannot postprocess status value: {}'.format(data['status']))
        return data


class IpInterface(Resource):

    oper_cmd = ["show ipv4 interface internal", "show vrrp brief"]
    oper_cmd_brief = None
    oper_cmd_filter = [lambda self, name: f'show ipv4 interface internal | utility egrep -A23  \'^{name} is\'']
    config_cmd = None
    config_cmd = "show running interface"
    config_cmd_filter = lambda self, name: f'sho running interface {name}'


class PolicyMap(Resource):

    oper_cmd = "show policy-map"
    oper_cmd_filter = lambda self, name: f'show policy-map pmap-name {name}'
    oper_cmd_brief = None
    config_cmd = "show running policy-map"
    config_cmd_filter = lambda self, name: f'show running policy-map {name}'

    @register('postprocess')
    def postprocess(self, data):
        regular_data = {'name': data['name'], 'classes': {}}
        current_class = None
        for rule in data['rules']:
            m = re.search(r' class (.*)', rule)
            if m:  # New class
                current_class = m.group(1)
                regular_data['classes'][current_class] = []
            else:
                regular_data['classes'][current_class].append(rule.lstrip())
        return regular_data


class ClassMap(Resource):

    oper_cmd = "show running class-map"
    oper_cmd_filter = lambda self, name: f'show running class-map {name}'
    oper_cmd_brief = None
    config_cmd = "show running class-map"
    config_cmd_filter = lambda self, name: f'show running class-map {name}'


class Acl(Resource):

    oper_cmd = "sho access-lists"
    oper_cmd_filter = lambda self, name: f'sho access-lists {name}'
    oper_cmd_brief = None
    config_cmd = "sho running-config ipv4 access-list"
    config_cmd_filter = lambda self, name: f'sho running-config ipv4 access-list {name}'

    @register('postprocess')
    def postprocess(self, data):
        regular_data = {'name': data['name'], 'af': data['af'], 'rules': []}
        for rule in data['rules']:
            m = re.search(r'(\d+) (\S+) (.*)', rule)
            if m:  # New class
                current_rule = {'seq': m.group(1), 'action': m.group(2), 'match': m.group(3)}
                regular_data['rules'].append(current_rule)
        return regular_data


class RoutePolicy(Resource):

    oper_cmd = "show rpl route-policy"
    oper_cmd_filter = lambda self, name: f'show rpl route-policy {name}'
    oper_cmd_brief = None
    config_cmd = "show rpl route-policy"
    config_cmd_filter = lambda self, name: f'show rpl route-policy {name}'

    @register('postprocess')
    def postprocess(self, data):
        regular_data = {'name': data['name'], 'policy': ""}
        if "args" in data.keys():
            regular_data['args'] = data.get('args')
        for rule in data['policy']:
            regular_data['policy'] += "\n" + rule
        regular_data['policy'] += "\n"
        return regular_data


class PrefixSet(Resource):

    oper_cmd = "show rpl prefix-set"
    oper_cmd_filter = lambda self, name: f'show rpl prefix-set {name}'
    oper_cmd_brief = None
    config_cmd = "show rpl prefix-set"
    config_cmd_filter = lambda self, name: f'show rpl prefix-set {name}'


class XConnect(Resource):
    oper_cmd = "show l2vpn xconnect detail"
    oper_cmd_filter = lambda self, group, name: f'show l2vpn xconnect group {group} xc-name {name} detail'
    oper_cmd_brief = None
    config_cmd = None
    config_cmd_filter = lambda self, group, name: f'show running-config l2vpn xconnect group {group} p2p {name}'


class VcEndpoint(Resource):

    oper_cmd = ["show l2vpn xconnect detail", "show l2vpn bridge-domain detail"]
    oper_cmd_filter = [lambda self, name: f'show l2vpn xconnect interface {name} detail', lambda self, name: f'show l2vpn bridge-domain interface {name} detail']
    oper_cmd_brief = None
    config_cmd = None
    config_cmd_filter = lambda self, name: f'sho running interface {name}'

    @register('reference')
    def vc(self):
        if 'vc_group' in self._rawdata.keys() and 'vc_name' in self._rawdata.keys() and 'vc_type' in self._rawdata.keys():
            if self._rawdata['vc_type'].lower() == "xc":
                return lambda self: self.device.get_resources('XConnect', filter={'name': self._rawdata['vc_name'], 'group': self._rawdata['vc_group']})[0]
            elif self._rawdata['vc_type'].lower() == "bridge":
                return lambda self: self.device.get_resources('BridgeDomain', filter={'name': self._rawdata['vc_name'], 'group': self._rawdata['vc_group']})[0]

    @register('postprocess')
    def postprocess(self, data):
        if 'encap_type' in data.keys():
            if data['encap_type'].lower() in ['vlan', '.1q', 'dot1q']:
                data['encap_type'] = "dot1q"
            elif data['encap_type'].lower() in ['ethernet', 'eth']:
                data['encap_type'] = "ethernet"
        else:
            data['encap_type'] = "none"
        if 'encap_outer' in data.keys():
            m = re.search(r'\[(\d+), (\d+)\]', data['encap_outer'])
            data['encap_outer'] = list(range(int(m.group(1)), int(m.group(2))+1))
        if 'vc_group' in data.keys() and 'vc_name' in data.keys() and 'vc_type' in data.keys():
            del data['vc_type']
            del data['vc_group']
            del data['vc_name']
        return data


class StaticRoute(Resource):

    oper_cmd = "show running router static | beg router static"
    oper_cmd_brief = None
    config_cmd = "show running router static | beg router static"


class Vrf(Resource):

    oper_cmd = 'sho vrf all ipv4 detail'
    oper_cmd_filter = lambda self, name: f'sho vrf {name} ipv4 detail'
    oper_cmd_brief = 'show vrf all'
    config_cmd = "show running-config vrf | beg vrf"
    config_cmd_filter = lambda self, name: f'show running vrf {name}'


class BgpRouter(Resource):

    oper_cmd = "show bgp process"
    oper_cmd_brief = None
    config_cmd = "show running router bgp"
    config_cmd_filter = lambda self: f'show running router bgp'


class Vrrp(Resource):

    oper_cmd = ["show vrrp detail"]
    oper_cmd_brief = None
    oper_cmd_filter = None
    config_cmd = None
    config_cmd_filter = lambda self, iface: f'sho running-config  router vrrp interface {iface}'


class BridgeDomain(Resource):

    oper_cmd = "show l2vpn bridge-domain"
    oper_cmd_filter = lambda self, group, name: f'show l2vpn bridge-domain group {group} bd-name {name} detail'
    oper_cmd_brief = None
    config_cmd = None
    config_cmd_filter = lambda self, group, name: f'show running l2vpn bridge group {group} bridge-domain {name}'

    @register('postprocess')
    def _postprocess_parsed_data(self, data):
        if data.get('ac_ifs'):
            data['ac_ifs'] = [self.device.lengthen_ifname(_) for _ in data['ac_ifs']]
        return data


class Vlan(Resource):

    oper_cmd = "show vlan"
    oper_cmd_brief = None
    config_cmd = None

    def __init(self, name, group, id, ac_ifs):
        self.name = name
        self.group = group
        self.id = id
        self.ac_ifs = ac_ifs
