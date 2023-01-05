import argparse
from src import Device
from src.resources import *

p = argparse.ArgumentParser()
p.add_argument("-u", "--user", required=True)
p.add_argument("-p", "--password", required=True)
args = p.parse_args()

args = {
  'username': args.user,
  'password': args.password
}
hostname = "par-th2-a9901-pe-01"
model = "ASR-9901"
my_device = Device(hostname=hostname, model=model, **args)

iface_name = 'GigabitEthernet102/0/0/33.2'
vcep = my_device.get_resources(class_name='VcEndpoint', filter={'name': iface_name})
c = vcep[0].get_running_config(follow_refs=True)

# Various Resource polling, filtering, configuration extraction and generation
ps = my_device.get_resources("PrefixSet", filter={'name': 'pfx-56844'})
ps[0].render(operation='add')
rps1 = my_device.get_resources("RoutePolicy", filter={'name': '9RLG-in'})
rps2 = my_device.get_resources("RoutePolicy", filter={'name': 'pfx-CELESTE-all'})
rps2[0].render(operation='add')
acls = my_device.get_resources("Acl")
pmaps = my_device.get_resources("PolicyMap", filter={'name': 'qos-out-child-cir40'})
vrfs = my_device.get_resources('Vrf')
vces = my_device.get_resources('VcEndpoint')
ipinterfaces = my_device.get_resources('IpInterface')
interfaces = my_device.get_resources('Interface', brief=True)
sr = my_device.get_resources('StaticRoute')
bds = my_device.get_resources('BridgeDomain')
interfaces = my_device.get_resources('Interface', brief=True)

# Resource creation and configuration generation
new_sr = my_device.add_resource(class_name="StaticRoute", data={'af': 'ipv4', 'destination': '78.31.40.4/30', 'nexthop': '91.90.103.207'})
config = new_sr.render(operation="add")

# Service type guessing from device interface
usages = my_device.guess_interface_usages('Bundle-Ether2.2515')
usages = my_device.guess_interface_usages('GigabitEthernet101/0/0/38.249')

# Sample L2VPN Port migration
iface_name = 'GigabitEthernet102/0/0/33.2'  # L2VPN ptp
localconfig = my_device.dig_configuration_from_interface(iface_name)
vcep = my_device.get_resources(class_name='VcEndpoint', filter={'name': iface_name})[0]
vc = vcep.vc
if vc.__class__.__name__ == "XConnect":  # Only Xconnects requires requires static remote configuration
  pass
  '''
  Resolve vc.remote_ip to remote_pe hostname and model (netbox)
  target_device = Device(hostname=remote_pe,  **args)
  if model == ASR*: # Remote model may have different Implementation for P2P L2VPN
    target_vc = remote_device.get_resources(class_name="XConnect", filter={'name'= vc.name})
    target_vc.remote_ip = local_pe_lo1_ipaddr4
    remote_config =  target_vc.config
  '''

# Sample L3VPN Port discovery
service_config = my_device.dig_configuration_from_interface('Bundle-Ether2.2524')  # L3VPN + BGP + route policies


exit('Tests ended')