import textfsm
import logging
from netmiko import ConnectHandler
import os
import json
import re
from jinja2 import Environment, FileSystemLoader
import ipaddress
import importlib
import inspect
from ciscoconfparse import CiscoConfParse

logger = logging.getLogger("logger")


class Device:
    def __init__(self, hostname, username, password, model):
        self.hostname = hostname
        self.model = model
        self.username = username
        self.password = password
        self.resources = {}
        self.configs = {}
        self.interface_name_maps = {}
        dir_path = os.path.dirname(os.path.realpath(__file__))
        self.dir = os.path.join(dir_path, 'resources/device_models/{}'.format(self.model))

        self.env = Environment(loader=FileSystemLoader(self.dir + "/templates"),
                               trim_blocks=True,
                               lstrip_blocks=True,
                               extensions=['jinja2.ext.do'],
                               newline_sequence='\n')
        sd_path = os.path.join(self.dir, 'syntax_definitions.json')
        with open(sd_path) as json_data:
            sr = json.load(json_data)
            for k, v in sr.items():
                setattr(self, k, v)

        self.conn = None
        self.ssh_connect()

    def ssh_connect(self):
        # mapping to netmiko os definitions
        _device_types = {
            "ASR9K": "cisco_xr",
            "ASR-9901": "cisco_xr",
            "NCS-5001": "cisco_xr",
            "NCS-5500": "cisco_xr",
            "default": "cisco_xe"
        }

        _device = {
            'device_type': None,
            'ip': self.hostname,
            'username': self.username,
            'password': self.password,
            'verbose': False,  # optional, defaults to False
        }
        if self.model in _device_types.keys():
            _device['device_type'] = _device_types[self.model]
        else:
            _device['device_type'] = _device_types["default"]
        try:
            if self.conn is None:
                self.conn = ConnectHandler(**_device)
            if not self.conn:
                raise ConnectionError('Failed to connect to {}'.format(self.hostname))
        except Exception as e:
            raise ConnectionError('Failed to connect to {}: {}'.format(self.hostname, e))

    def ssh_disconnect(self):
        self.conn.disconnect()

    def shorten_ifname(self, s):
        for k, v in self.interface_name_maps.items():
            if v in s:
                return s.replace(v, k)
        return s

    def lengthen_ifname(self, s):
        for k, v in self.interface_name_maps.items():
            if v not in s and k in s:
                return s.replace(k, v)
        return s

    def exec(self, cmd):
        data = self.conn.send_command(cmd, read_timeout=120)
        return data

    def get_config(self, class_name, force_refresh=True):

        if not force_refresh and not self.configs.get(class_name):
            force_refresh = True
        if force_refresh:
            resource_class = getattr(importlib.import_module("devicemanager.resources.device_models.{}".format(self.model)), class_name)

            cmd = resource_class.config_cmd
            if not cmd:
                raise AttributeError('{} resource has no config_cmd attribute set'.format(class_name))
            config = self.exec(cmd)
            self.configs[class_name] = config
        return self.configs[class_name]

    def get_resources(self, class_name, force_refresh=False, brief=False, filter = None):
        """
        Gets all resources of class <class_name> existing on self
        For performance reason, fetced data is cached on sefl Object. This can be avoided using <force_refesh> param.
        :param class_name: Class name of resources to be fetched
        :param force_refresh: Weter to force cache_update or not
        :return:
        """

        resource_class = getattr(importlib.import_module("devicemanager.resources.device_models.{}".format(self.model)), class_name)
        refresh = False
        if force_refresh or not force_refresh and not self.resources.get(class_name):
            refresh = True
        if refresh:
            data = ""
            if brief:
                if filter:
                    raise AttributeError('Cannot use brief and filter simultaneously')
                if resource_class.oper_cmd_brief:
                    cmd = resource_class.oper_cmd_brief
                    template_name = "{}_brief.textfsm".format(class_name)
                else:
                    raise AttributeError("brief param requires specific command in {}/models.py".format(""))
            elif filter:
                if resource_class.oper_cmd_filter:
                    cmd = resource_class.oper_cmd_filter
                    template_name = "{}.textfsm".format(class_name)
                else:
                    raise AttributeError("filter param requires tfsm brief template")
            else:  # Get all detailed resource
                cmd = resource_class.oper_cmd
                template_name = "{}.textfsm".format(class_name)

            tfsm = textfsm.TextFSM(open(os.path.join(self.dir, "templates/", template_name)))

            if isinstance(cmd, list):  # May use output from multiple commands
                for c in cmd:
                    if filter:
                        # params_names = inspect.getfullargspec(c).args
                        # params = {arg: getattr(resource_class, arg) for arg in params_names if arg != "self"}
                        c = c(resource_class, **filter)
                    data = data + "\n" + self.exec(c)
            else:
                if filter:
                    try:
                        cmd = cmd(resource_class, **filter)
                    except TypeError as e:
                        raise ValueError("Some filter attributes doesnt match {} model".format(class_name))
                data = self.exec(cmd)

            parsed_data = tfsm.ParseText(data)
            resources = []
            raw_datas = [{key: item[tfsm.header.index(key)] for key in tfsm.header if key != 'selector' and item[tfsm.header.index(key)] != ''} for item in parsed_data]

            for rd in raw_datas:
                r = resource_class(device=self, raw_data=rd)
                resources.append(r)
            if filter:  # Consider caching data if complete resource set
                return resources
            else:
                self.resources[class_name] = resources
                return self.resources[class_name]
        else:
            if filter:  # Proceed data caching only if dealing with unfiltered resource set
                filtered_resources = []
                for resource in self.resources[class_name]:
                    match = all([getattr(resource, k) == v for k, v in filter.items()])
                    if match:
                        filtered_resources.append(resource)
                return filtered_resources
            else:
                return self.resources[class_name]

    def add_resource(self, class_name, data={}):
        """
        Creates new resource of resource_class Class on self Device.
        Returns this new Resource
        :param class_name: Class name of resources to be created
        :param data: Resource characteristics
        :return: Newly created resource
        """
        ressource_cls = getattr(importlib.import_module("devicemanager.resources.device_models.{}".format(self.model)), class_name)
        r = ressource_cls(device=self, raw_data=data)

        self.resources[class_name].append(r)
        return r

    def interface_replace_slot_id(self, if_name, slot_id):
        """
        helper function generating an updated interface name where slot_id is replaced. Syntax is platform dependent.
        :param self:
        :param if_name: Original interface name
        :param slot_id: Target slot ID to move to
        :return: Updates interface name
        """
        if self.model == "ASR9K Series":
            return re.sub("(\D+)(\d+)((\/\d+)+)", "\g<1>{}\\3".format(slot_id), if_name)
        else:
            raise Exception('Unsupported Device model for {}'.format(self.hostname))

    @staticmethod
    def hostname_fix(hostname):  # FIXME move this to configuration
        maps = {"\.xxx\.f$": ".xxx.fr"}
        for pattern, v in maps.items():
            fix = re.subn(r"(.*)({})(.*)".format(pattern), r"\1{}\3".format(v), hostname)
            if fix[1]:
                return fix[0]

        fix2 = re.subn(r"(.*-\d{2})\.xxx\.fr", r"\1.admin.xxx.fr", hostname)
        if fix2[1]:
            return fix2[0]
        return hostname

    def config_section_selector(self, config, item):
        if self.platform == 'iosxr':
            parser = CiscoConfParse(config.split('\n'))
            upper_cfg = parser.find_parents_w_child('router', item['name'], item.get('value'))
            selected_cfg = parser.find_all_children('{} {}'.format(item.get('name'), item.get('value')))
            assembled_cfg = upper_cfg + selected_cfg
            return '\n'.join(assembled_cfg)
        else:
            raise ValueError('Config selection not implemented for such platform {}'.format(self.platform))

    def strip_config_junk(self, config):
        for expr in self.config_junks:
            config = re.sub(expr, "", config)
        return config

    def guess_interface_usages(self, interface_name):
        """
        Tries to guess wich kind of service this interface is used for
        :param interface_name:
        :return: Service type [l2vpn|l3vpn|l3inet]
        """
        usages = []
        ip_interfaces = self.get_resources("IpInterface", filter={'name': interface_name})
        if len(ip_interfaces):
            if ip_interfaces[0].vrf == "default":
                usages.append("l3inet")
            elif "vpn" in ip_interfaces[0].vrf:
                usages.append("l3vpn")
        vc_endpoints = self.get_resources("VcEndpoint", filter={'name': interface_name})
        if len(vc_endpoints):
            if "dot1q" in vc_endpoints[0].encap_type:
                usages.append("l2vpn")
        return usages

    def dig_configuration_from_interface(self, interface_name):
        usages = self.guess_interface_usages(interface_name)

        if self.platform in ["iosxe"]:
            return self._dig_configuration_from_iosxe_interface(interface_name)
        elif self.platform in ["iosxr"]:
            if "l3vpn" in usages or "l3inet" in usages:
                return self._dig_l3_configuration_from_iosxr_interface(interface_name)
            elif "l2vpn" in usages:
                return self._dig_l2_configuration_from_iosxr_interface(interface_name)
            else:
                raise Exception('Interface {} has no or undiscoverable usages: {}'.format(interface_name, usages))
        else:
            raise Exception('Unsupported device model {}'.format(self.model))

    def _dig_configuration_from_iosxe_interface(self, interface_name):
        ip_interfaces = self.get_resources("IpInterface")
        vrrps = self.get_resources("Vrrp")
        static_routes = self.get_resources("StaticRoute")
        vrfs = ["L2L"]
        route_policies = []  # List of custom route policy names
        prefix_lists = []
        config = ""
        # Fetch BGP ipv4 AF config once
        try:
            cmd = self.config_parsing_scheme.get("Bgp")['cmd']
        except:
            raise Exception('Failed to get Static Route cmd in resource parsing scheme')
        r = self.exec(cmd)
        r = re.split(r'\n(?= vrf)', r)[0]
        bgp_ipv4af_lines = r.split('\n')
        bgp_ipv4af = re.split(r'\n(?= neighbor .*)\n', r)[0] #  Common BGP AF configuration
        bgp_ipv4af_nei = [_ for _ in bgp_ipv4af_lines if re.match(r' neighbor .*', _)]

        # Fetch route static ipv4 AF config once
        try:
            cmd = self.config_parsing_scheme.get("StaticRoute")['cmd']
        except:
            raise Exception('Failed to get Static Route cmd in resource parsing scheme')
        r = self.exec(cmd)

        try:
            ip_interface = [_ for _ in ip_interfaces if _['name'] == interface_name][0]
        except:
            raise Exception('Interface {} not found on this device ({})'.format(interface_name, self.hostname))

        if ip_interface.get('vrf') and ip_interface['vrf'] not in vrfs:
            cmd = 'sho running vrf {} | section vrf definition'.format(ip_interface['vrf'])
            r = self.exec(cmd)
            route_policies.extend([x[1] for x in re.findall("(import|export) route-policy (\S+)", r)])
            config = config + r + '\n\n'
            vrfs.append(ip_interface['vrf'])
        else:
            pass
        config_subif = ""
        cmd = 'sho running interf {} | beg interface'.format(ip_interface['name'])
        config_subif = self.exec(cmd)
        # TODO config_subif = config_subif.replace(interface_name, dstiface)
        config_qos = ""
        config_acl = ""
        m = re.findall(" service-policy (input|output) ({})\n".format(self.resource_naming_conventions['l3']['custom_service_policy_pattern']), config_subif)  # Find qos policy
        if m:
            for pm in m:
                cmd = "sho running-config policy-map {} | begin policy-map".format(pm[1])
                config_qos = config_qos + self.exec(cmd) + '\n'
                m = re.findall("\s\sservice-policy (qos-\S+-\d+)\n", config_qos)  # Look for nested policy
                if m:
                    for pm in m:
                        cmd = "sho running-config policy-map {} | begin policy-map".format(pm)
                        config_qos = self.exec(cmd) + '\n' + config_qos
                        m = re.findall(" class (qos-cm\S+-\d+)\n", config_qos)  # Look for nested custom policy
                        if m:
                            for cm in m:
                                cmd = "sho running-config class-map {} | begin class-map".format(cm)
                                config_qos = self.exec(cmd) + '\n' + config_qos
                    acls = re.findall("match access-group ipv4 (qos-acl-\S+-\d+)", config_qos)  # Look for nested policy
                    if acls:
                        for acl in acls:
                            #cmd = "sho running-config ipv4 access-list {} | begin policy-map".format(acl)
                            try:
                                cmd = self.config_parsing_scheme.get("AccessList")['cmd']
                            except:
                                raise Exception('Failed to get AccessListe cmd in config parsing scheme')
                            config_acl = self.exec(cmd) + '\n' + config_acl
        config = config + config_qos + config_acl + config_subif + '\n'

        # BGP routing configuration
        config_bgp = ""
        pl_config = ""
        rp_config = ""
        pg_config = ""
        if ip_interface.get('vrf') and ip_interface['vrf'] != "default":
            #cmd = 'sho running-config router bgp 34177 vrf {}'.format(ip_interface['vrf'])
            cmd = 'sho running-config partition router bgp 34177 | section address-family ipv4 vrf {}'.format(ip_interface['vrf'])
            r = self.exec(cmd)
            if not r in ["% No such configuration item(s)\n", ""]:
                bgp = "router bgp 34177\n" + re.split(r'\n(?=  neighbor )', r)[0]
                route_policies.extend([x for x in re.findall(" route-policy (\S+)\n", bgp)])
                bgp_lines = r.split('\n')
                bgp_nei = [_ for _ in bgp_lines if re.match(r'\s+neighbor\s', _)]

                # bgp_nei = re.split(r'\n(?=  neighbor )', r)[1:]
                config_bgp = config_bgp + bgp + '\n\n'
            else:
                config_bgp = "\n"
        else:
            # Handle ipv4 AF
            bgp = bgp_ipv4af
            bgp_nei = bgp_ipv4af_nei
            config_bgp = config_bgp + bgp.split('\n')[0] + '\n'  # Keep only router bgp section command

        selected_nei = ""
        for n in bgp_nei:
            m = re.search("^\s+neighbor (\d+\.\d+\.\d+\.\d+) ", n)
            if m:
                nei_ipaddr4 = m.group(1)
                if ipaddress.ip_address(nei_ipaddr4) in ipaddress.IPv4Interface('{}/{}'.format(ip_interface['ipaddr4'], ip_interface['ipmask4'])).network:
                    selected_nei += "\n" + n
                    m = re.search(" peer-group (.*-\d+)$", n)  # Look for nested policy
                    if m:
                        cmd = "sho running-config partition router bgp 34177 | inc neighbor {} ".format(m.group(1))
                        selected_nei = self.exec(cmd) + '\n'

        if len(selected_nei):
            config_bgp = config_bgp + selected_nei + '\n'
            m = re.findall("\s+route-map (\S+) (in|out)\n", config_bgp)  # Find Custion prefix-sets
            if m:
                for rp in m:
                    if rp[0] not in route_policies:
                        route_policies.append(rp[0])

            m = re.findall(" prefix-list (.+) (in|out)\n", config_bgp)  # Look for nested policy
            if m:
                for pl in m:
                    if pl[0] not in prefix_lists:
                        prefix_lists.append(pl[0])
        else:
            logger.warning("No BGP neighbor found for interface {} ({})".format(ip_interface['name'], '{}/{}'.format(ip_interface['ipaddr4'], ip_interface['ipmask4'])))
        if config_bgp.strip('\n') == 'router bgp 34177':
            logger.debug("BGP config is useless, clearing it")
            config_bgp = ""

        # Static routing configuration
        selected_routes = []
        for sr in static_routes:
            try:
                if ip_interface.get('vrf') and ip_interface['vrf'] == sr.get('vrf') or (not ip_interface.get('vrf') and not sr.get('vrf')):
                    if ipaddress.ip_address(sr['nexthop']) in ipaddress.IPv4Interface('{}/{}'.format(ip_interface['ipaddr4'], ip_interface['ipmask4'])).network:
                        selected_routes.append(sr)
            except ValueError as e:
                logger.debug('Skipping StaticRoute: {}'.format(str(e)))

        config_static = ""
        for sr in selected_routes:
            config_static = config_static + self.render('add', 'StaticRoute', sr)

        if len(selected_routes):
            logger.warning("Static route found for interface {} ({})".format(ip_interface['name'], '{}/{}'.format(ip_interface['ipaddr4'], ip_interface['ipmask4'])))
        else:
            logger.debug("No static route found for interface {} ({})".format(ip_interface['name'], '{}/{}'.format(ip_interface['ipaddr4'], ip_interface['ipmask4'])))

        rp_config = ""
        for rp in route_policies:
            cmd = "sho running-config partition route-map  | section {}".format(rp)
            rp_config = rp_config + self.exec(cmd) + '\n\n'
        pl_config = ""
        for pl in prefix_lists:
            cmd = "sho running-config | inc ip prefix-list {} ".format(pl)
            pl_config = pl_config + self.exec(cmd) + '\n\n'

        config_vrrp = ""
        for v in vrrps:
            long_ifname = self.lengthen_ifname(v['name'])
            if ip_interface['name'] == long_ifname:
                # TODO v['name'] = long_ifname.replace(interface_name, dstiface)
                config_vrrp = self.render('add', 'Vrrp', v)
                logger.warning("Found VRRP for interface {}".format(ip_interface['name']))

        output = config + pl_config + rp_config + config_bgp + config_static + config_vrrp + '\nroot\n\n\n\n\n'
        output = re.sub("Current configuration.*bytes\n", "", output)
        output = re.sub("\S+\s\S+\s+\d+\s\d+:\d+:\d+\.\d+\s\S+\n", "", output)
        output = re.sub("% Invalid.*marker\.\n", "", output)
        return output

    def _dig_l3_configuration_from_iosxr_interface(self, interface_name):

        vrrps = self.get_resources("Vrrp")
        static_routes = self.get_resources("StaticRoute")
        # Following Lists stores resources we consider not being as part of base config (Infra Ansible managed)
        well_known_vrf_names = ["L2L", "default"]
        well_known_classmaps = ['qos-cm-EF-out', 'qos-cm-LEF-out', 'qos-cm-IF-out', 'qos-cm-BBE-out', 'qos-cm-BE-out', 'qos-cm-LBE-out', 'class-default']
        well_known_acls = []
        well_known_policymaps = ["qos-in-child", "qos-out-child"]
        well_known_routepolicies = []
        # Following List are designed to store discovered resources we want to get part of service configuration
        collected_route_policies = []  # List of custom route policy names
        collected_acls = []
        collected_cmaps = []
        collected_pmaps = []
        collected_prefix_lists = []
        collected_vrf = []
        config = ""
        try:
            ip_interface = self.get_resources("IpInterface", filter={'name': interface_name})[0]
        except Exception as e:
            raise Exception('Interface {} not found on this device ({})'.format(interface_name, self.hostname))

        if ip_interface.vrf not in well_known_vrf_names:
            collected_vrf = self.get_resources("Vrf", filter={"name": ip_interface.vrf})[0]
            if collected_vrf.import_policy and collected_vrf.import_policy not in collected_route_policies:
                collected_route_policies.append(collected_vrf.import_policy)
            if collected_vrf.export_policy and collected_vrf.export_policy not in collected_route_policies:
                collected_route_policies.append(collected_vrf.export_policy)

        m = re.findall(" service-policy (input|output) ({})\n".format(self.resource_naming_conventions['l3']['custom_service_policy_pattern']), ip_interface.running_config)  # Find qos policy
        if m:
            for pm in m:
                pmap = self.get_resources("PolicyMap", filter={"name": pm[1]})[0]
                if pm[1] not in well_known_policymaps:
                    if pmap.name not in [_.name for _ in collected_pmaps]:
                        collected_pmaps.append(pmap)
                matches = re.findall("\s\sservice-policy (\S+)\n", pmap.running_config)  # Look for nested policies
                if matches:
                    for match in matches:
                        npmap = self.get_resources("PolicyMap", filter={"name": match})[0]
                        if npmap.name not in [_.name for _ in collected_pmaps]:
                            collected_pmaps.append(npmap)
            for pm in collected_pmaps:
                class_names = re.findall("\sclass\s(\S+)\n", pm.running_config)  # Inspecting collected pmaps for class or acl references
                if class_names:
                    for class_name in class_names:
                        if class_name not in well_known_classmaps:
                            cmap = self.get_resources("ClassMap", filter={"name": class_name})[0]
                            if cmap.name not in [_.name for _ in collected_cmaps]:
                                collected_cmaps.append(cmap)
                            acl_names = re.findall("match access-group ipv4 (\S+)", cmap.running_config)  # Look for nested policy
                            if acl_names:
                                for acl_name in acl_names:
                                    if acl_name not in well_known_acls:
                                        acl = self.get_resources("Acl", filter={"name": acl_name})[0]
                                        if acl.name not in [_.name for _ in collected_acls]:
                                            collected_acls.append(acl)

        # BGP routing configuration
        config_bgp = ""
        router_bgp = self.get_resources("BgpRouter")[0]
        if ip_interface.vrf == "default":  # BGP config for internet routing (ipv4 address family)
            #config_router_ipv4_bgp = re.split(r'\n(?= vrf )', router_bgp.running_config)[0]
            bgp_ipv4_cfg_part = re.split(r'\n(?=\s+neighbor )', config_router_bgp_vrf)[0]
            bgp_ipv4_neighbors_cfg_parts = re.split(r'\n(?=\s+neighbor )', config_router_bgp_vrf)[1:]
            bgp_neighbors = bgp_ipv4_neighbors_cfg_parts  # Store for later neighbor config selection
            config_bgp = bgp_ipv4_cfg_part + router_bgp.running_config.split('\n')[0] + '\n'  # Keep only router bgp section command
        else:   # BGP config for routing within L3VPN
            config_router_bgp_vrf = self.config_section_selector(config=router_bgp.running_config, item={"name": "vrf", "value": ip_interface.vrf})
            if not config_router_bgp_vrf == "\n":
                bgp_vrf_cfg_part = re.split(r'\n(?=\s+neighbor )', config_router_bgp_vrf)[0]
                bgp_vrf_neighbors_cfg_parts = re.split(r'\n(?=\s+neighbor )', config_router_bgp_vrf)[1:]
                for rp_name in re.findall("\s+route-policy (\S+)\n", config_router_bgp_vrf):
                    if rp_name not in [_.name for _ in collected_route_policies] and rp_name not in well_known_routepolicies:
                        rp = self.get_resources("RoutePolicy", filter={"name": rp_name})[0]
                        collected_route_policies.append(rp)
                bgp_neighbors = bgp_vrf_neighbors_cfg_parts  # Store for later neighbor config selection
                config_bgp += bgp_vrf_cfg_part + "\n"
            else:
                config_bgp = ""

        selected_nei = None
        for n in bgp_neighbors:
            m = re.search("^\s+neighbor (\d+\.\d+\.\d+\.\d+)", n)
            if m:
                nei_ipaddr4 = m.group(1)
                if ipaddress.ip_address(nei_ipaddr4) in ipaddress.IPv4Interface('{}/{}'.format(ip_interface.ipaddr4, ip_interface.ipmask4)).network:
                    selected_nei = n
                    break
        if selected_nei:
            config_bgp = config_bgp + selected_nei + '\n'
            m = re.findall("\s+route-policy (\S+)\(({})\) (in|out)".format(self.resource_naming_conventions['l3']['custom_prefix_list_pattern']), selected_nei)  # Find Custion prefix-sets
            for match in m:
                if match[0] not in [_.name for _ in collected_route_policies]:
                    collected_route_policies.append(self.get_resources("RoutePolicy", filter={"name": match[0]})[0])
                if match[1] not in [_.name for _ in collected_prefix_lists]:
                    collected_prefix_lists.append(self.get_resources("PrefixSet", filter={"name": match[1]})[0])

        else:
            logger.warning("No BGP neighbor found for interface {} ({})".format(ip_interface.name, '{}'.format(ip_interface.ipaddr4)))
        if config_bgp.strip('\n') == 'router bgp 34177':
            logger.debug("BGP config is useless, clearing it")
            config_bgp = ""

        # Static routing configuration
        selected_routes = []
        for sr in static_routes:
            try:
                # TODO fix ipmask4 value polling
                if ipaddress.ip_address(sr.nexthop) in ipaddress.IPv4Interface('{}/{}'.format(ip_interface.ipaddr4, ip_interface.ipmask4)).network:
                    selected_routes.append(sr)
            except ValueError as e:
                logger.debug('Skipping StaticRoute: {}'.format(str(e)))

        config_static = ""
        for sr in selected_routes:
            config_static += self.render('add', 'StaticRoute', sr)

        if len(selected_routes):
            logger.warning("Static route found for interface {} ({})".format(ip_interface.name, '{}/{}'.format(ip_interface.ipaddr4, ip_interface.ipmask4)))
        else:
            logger.debug("No static route found for interface {} ({})".format(ip_interface.name, '{}/{}'.format(ip_interface.ipaddr4, ip_interface.ipmask4)))

        config_acl = ""
        for acl in collected_acls:
            config_acl += acl.render(operation='add')
        config_prefix = ""
        for pl in collected_prefix_lists:
            config_prefix += pl.render(operation='add')
        config_cmap = ""
        for cm in collected_cmaps:
            config_cmap += cm.render(operation='add')
        config_rp = ""
        for rp in collected_route_policies:
            config_prefix += rp.render(operation='add')

        config_vrf = collected_vrf.running_config

        config_vrrp = ""
        for v in vrrps:
            long_ifname = self.lengthen_ifname(v.iface)
            if ip_interface.name == long_ifname:
                config_vrrp += v.render(operation='add') + "\n"
                logger.warning("Found VRRP for interface {}".format(ip_interface.name))

        output = config + config_acl + config_prefix + config_cmap + config_rp + config_vrf + config_bgp + config_static + config_vrrp + '\nroot\n'
        # Strip noisy output that may remain

        return self.strip_config_junk(output)

    def _dig_l2_configuration_from_iosxr_interface(self, interface_name):
        xconnects = self.get_resources(class_name="XConnect")
        bridge_domains = self.get_resources(class_name="BridgeDomain")
        well_known_classmaps = ['qos-cm-EF-out', 'qos-cm-LEF-out', 'qos-cm-IF-out', 'qos-cm-BBE-out', 'qos-cm-BE-out', 'qos-cm-LBE-out', 'class-default']
        well_known_acls = []
        well_known_policymaps = ["qos-in-child", "qos-out-child"]
        # Following List are designed to store discovered resources we want to get part of service configuration
        collected_acls = []
        collected_cmaps = []
        collected_pmaps = []
        collected_xc = None
        collected_bd = None

        vc_endpoint = self.get_resources(class_name="VcEndpoint", filter={'name': interface_name})[0]
        lo1_iface = self.get_resources(class_name="IpInterface", filter={'name': 'Loopback1'})[0]
        local_l2vpn_addr = lo1_iface.ipaddr4

        config_acl = ""
        config_cmap = ""
        config_pmap = ""
        config_subif = vc_endpoint.running_config

        m = re.findall(" service-policy (input|output) ({})\n".format(self.resource_naming_conventions['l2']['custom_service_policy_pattern']), config_subif)  # Find qos policy
        if m:
            for pm in m:
                pmap = self.get_resources("PolicyMap", filter={"name": pm[1]})[0]
                if pm[1] not in well_known_policymaps:
                    if pmap.name not in [_.name for _ in collected_pmaps]:
                        collected_pmaps.append(pmap)
                matches = re.findall("\s\sservice-policy (\S+)\n", pmap.running_config)  # Look for nested policies
                if matches:
                    for match in matches:
                        if match not in well_known_policymaps + [_.name for _ in collected_pmaps]:
                            collected_pmaps.append(npmap)
                            npmap = self.get_resources("PolicyMap", filter={"name": match})[0]
            for pm in collected_pmaps:
                class_names = re.findall("\sclass\s(\S+)\n", pm.running_config)  # Inspecting collected pmaps for class or acl references
                if class_names:
                    for class_name in class_names:
                        if class_name not in well_known_classmaps + [_.name for _ in collected_cmaps]:
                            cmap = self.get_resources("ClassMap", filter={"name": class_name})[0]
                            collected_cmaps.append(cmap)
                            acl_names = re.findall("match access-group ipv4 (\S+)", cmap.running_config)  # Look for nested policy
                            if acl_names:
                                for acl_name in acl_names:
                                    if acl_name not in well_known_acls + [_.name for _ in collected_acls]:
                                        acl = self.get_resources("Acl", filter={"name": acl_name})[0]
                                        collected_acls.append(acl)

        if vc_endpoint.vc:
            config_vc = vc_endpoint.vc.running_config
        else:
            logger.info('This enpdoint has no L2VPN attached: {}'.format(vc_endpoint.name))

        config_vc = re.sub(r'   interface (?!{})(\n|.)+?!'.format(vc_endpoint.name), '', config_vc)  # This may include unwanted other AC interfaces, strip them

        for acl in collected_acls:
            config_acl += acl.render(operation="add")
        for cmap in collected_cmaps:
            config_cmap += cmap.render(operation="add")
        for pmap in collected_pmaps:
            config_pmap += pmap.render(operation="add")

        config = config_acl + "\n" + config_cmap + "\n" + config_pmap + "\n" + config_subif + "\n" + config_vc + "\n"
        config = self.strip_config_junk(config)
        return config
