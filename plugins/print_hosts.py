import ipaddress
import logging

import xml.etree.ElementTree as ET

from common.utils import get_nessus_hostproperty_by_name

PLUGIN_NAME = __name__.rsplit(".", 1)[1]

logger = logging.getLogger(__name__)


def insert_subparser(subparser):
    arg_parser = subparser.add_parser(PLUGIN_NAME, help="Print information about hosts present in the Nessus scan file. Default action: print host details")
    arg_parser.set_defaults(handler=handle)
    arg_parser.set_defaults(parser=PLUGIN_NAME)

    mutual_ex_parser = arg_parser.add_mutually_exclusive_group()
    mutual_ex_parser.add_argument("--host-details", help="Print data about each host", action="store_true")
    mutual_ex_parser.add_argument("--socket-addrs", help="Print all socket addresses (i.e. \"10.20.30.40:8080\")", action="store_true")
    mutual_ex_parser.add_argument("--host-ports", help="Print open ports per host (e.g. \"10.20.30.40: UDP/137,TCP/443,TCP/8080\")", action="store_true")

    mutual_ex_parser2 = arg_parser.add_mutually_exclusive_group()
    mutual_ex_parser2.add_argument("--by-ip", help="Designate hosts by their IP only", action="store_true", default=False)
    mutual_ex_parser2.add_argument("--by-fqdn", help="Designate hosts by FQDN only (falls back to IP no FQDN reported)", action="store_true", default=False)

def handle(args):
    if args.host_details:
        res = get_host_details(args)

    elif args.socket_addrs:
        res = get_socket_addresses(args)

    elif args.host_ports:
        res = get_ports_by_host(args)

    else:
        logger.info("No action was specified. Defaulting to printing host details.")
        res = get_host_details(args)

    print(res)
    return res

def get_host_details(args):
    tree = ET.parse(args.input_file)
    root = tree.getroot()

    res = dict()
    for host in root.iter("ReportHost"):
        hostprops = host.find("HostProperties")
        _ip = get_nessus_hostproperty_by_name(hostprops, "host-ip")
        _fqdn = get_nessus_hostproperty_by_name(hostprops, "host-fqdn", None)
        name = get_host_displayname(_ip, _fqdn, args.by_ip, args.by_fqdn)
        tags = dict()
        for tag in host.find("HostProperties"):
            tags[tag.get("name").title()] = tag.text
        host_res = f"Report Host Name: {name}\n"
        for k in sorted(tags.keys()):
            host_res += f"\t{k}: {tags[k]}\n"
        res[name] = host_res

    if args.by_ip:
        sorted_res = [res[k] for k in sorted(res.keys(), key=lambda x: ipaddress.ip_address(x))]
    else:
        sorted_res = [res[k] for k in sorted(res.keys())]

    return "\n".join(sorted_res)

def get_socket_addresses(args):
    tree = ET.parse(args.input_file)
    root = tree.getroot()

    res = set()
    for host in root.iter("ReportHost"):
        hostprops = host.find("HostProperties")
        _ip = get_nessus_hostproperty_by_name(hostprops, "host-ip")
        _fqdn = get_nessus_hostproperty_by_name(hostprops, "host-fqdn", None)
        name = get_host_displayname(_ip, _fqdn, args.by_ip, args.by_fqdn)
        for finding in host.iter("ReportItem"):
            port = finding.get("port")
            if int(port) == 0:
                plugin_name = finding.get("pluginName")
                logger.debug(f"Finding \"{plugin_name}\" does not have a port. Skipping it.")
                continue
            
            res.add(f"{name}:{port}")

    if args.by_ip:
        sorted_res = sorted(res, key=lambda x: (ipaddress.ip_address(x.split(":")[0]), int(x.split(":")[1])))
    else:
        sorted_res = sorted(res, key=lambda x: (x.split(":")[0], int(x.split(":")[1])))

    return "\n".join(sorted_res)

def get_ports_by_host(args):
    tree = ET.parse(args.input_file)
    root = tree.getroot()

    res = dict()
    for host in root.iter("ReportHost"):
        hostprops = host.find("HostProperties")
        _ip = get_nessus_hostproperty_by_name(hostprops, "host-ip")
        _fqdn = get_nessus_hostproperty_by_name(hostprops, "host-fqdn", None)
        name = get_host_displayname(_ip, _fqdn, args.by_ip, args.by_fqdn)
        for finding in host.iter("ReportItem"):
            port = finding.get("port")
            protocol = finding.get("protocol")
            if int(port) == 0:
                plugin_name = finding.get("pluginName")
                logger.debug(f"Finding \"{plugin_name}\" does not have a port. Skipping it.")
                continue
        
            if name in res:
                res[name].add(f"{protocol.upper()}/{port}")

            else:
                res[name] = {f"{protocol.upper()}/{port}"}

    if args.by_ip:
        sorted_keys = sorted(res.keys(), key=lambda x: ipaddress.ip_address(x))
    else: 
        sorted_keys = sorted(res.keys())
    sorted_res = []
    for k in sorted_keys:
        sorted_ports = sorted(res[k], key=lambda x: int(x.split("/")[1]))
        sorted_res.append(f"{k}\t{','.join(sorted_ports)}")

    return "\n".join(sorted_res)

def get_host_displayname(ip, fqdn, by_ip, by_fqdn):
    if by_ip:
        return ip
    elif by_fqdn:
        return fqdn or ip
    return f"{ip} ({fqdn})"