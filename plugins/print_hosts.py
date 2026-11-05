import ipaddress
import logging

import lxml.etree as ET

from common.utils import get_nessus_hostproperty_by_name, get_xml_context_from_file, get_host_displayname

PLUGIN_NAME = __name__.rsplit(".", 1)[1]

logger = logging.getLogger(__name__)


def insert_subparser(subparser):
    arg_parser = subparser.add_parser(PLUGIN_NAME, help="Print information about hosts present in the Nessus scan \
                                      file. Default action: print host details")
    arg_parser.set_defaults(handler=handle)
    arg_parser.set_defaults(parser=PLUGIN_NAME)

    mutual_ex_parser = arg_parser.add_mutually_exclusive_group()
    mutual_ex_parser.add_argument("--host-details", help="Print data about each host", 
                                  action="store_true")
    mutual_ex_parser.add_argument("--socket-addrs", help="Print all socket addresses (i.e. \"10.20.30.40:8080\")", 
                                  action="store_true")
    mutual_ex_parser.add_argument("--host-ports", 
                                  help="Print open ports per host (e.g. \"10.20.30.40: 137/udp,443/tcp,8080/tcp\")", 
                                  action="store_true")

    mutual_ex_parser2 = arg_parser.add_mutually_exclusive_group()
    mutual_ex_parser2.add_argument("--by-ip", help="Designate hosts by their IP only", 
                                   action="store_true", default=False)
    mutual_ex_parser2.add_argument("--by-fqdn", help="Designate hosts by FQDN only (falls back to IP no FQDN reported)", 
                                   action="store_true", default=False)

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
    host_details = _parse_host_details(args)

    res = ""
    for host in host_details:
        name = get_host_displayname(host['name'], host['ip_address'], host['name'], args.by_ip, args.by_fqdn)
        res += f"ReportHost: {name}\n"
        for key in sorted(host.keys()):

            if key == 'raw_host_properties':
                continue

            res += f"\t{key}: {str(host[key])}\n"
        res += f"\t{'raw_host_properties'}: {str(host['raw_host_properties'])}\n"
        res += "\n"

    return res

def get_socket_addresses(args):
    host_details = _parse_host_details(args)

    res = ""
    for host in host_details:
        for port in host["open_ports"]:
            name = get_host_displayname(host['name'], host['ip_address'], host['name'], args.by_ip, args.by_fqdn)
            res += f"{name}:{port}\n"
    return res
    

def get_ports_by_host(args):
    host_details = _parse_host_details(args)

    res = ""
    for host in host_details:
        name = get_host_displayname(host['name'], host['ip_address'], host['name'], args.by_ip, args.by_fqdn)
        res += f"{name}: {','.join(host["open_ports"])}\n"
    return res


def _parse_host_details(args):

    def sort_ports(item):
        item_port, item_protocol = item.split("/")
        return (item_port, item_protocol)

    details = []

    context = get_xml_context_from_file(args, tag="ReportHost")
    for _, host in context:
        hostprops = host.find("HostProperties")

        ip = get_nessus_hostproperty_by_name(hostprops, "host-ip", None)
        fqdn = get_nessus_hostproperty_by_name(hostprops, "host-fqdn", None)
        name = host.get("name", None)

        hostprop_dict = dict()
        for tag in hostprops:
            hostprop_dict[tag.get("name").lower()] = tag.text

        finding_count = 0
        open_ports = set()
        for _, finding in ET.iterwalk(host, tag="ReportItem"):
            finding_count += 1
            port = finding.get("port")
            protocol = finding.get("protocol")
            if int(port) == 0:
                plugin_name = finding.get("pluginName")
                logger.debug(f"Finding \"{plugin_name}\" does not have a port. Skipping it.")
                finding.clear()
                continue
            open_ports.add(f"{port}/{protocol}")

        details.append(
            {
                "name" : name,
                "fqdn": fqdn,
                "ip_address": ip,
                "rdns": hostprop_dict.get("host-rdp", None),
                "credentialed_scan": hostprop_dict.get("credentialed_scan", None),
                "scan_start": hostprop_dict.get("host_start", None),
                "scan_end": hostprop_dict.get("host_end", None),
                "total_report_findings": finding_count,
                "total_open_ports": len(open_ports),
                "open_ports": list(sorted(open_ports, key=sort_ports)),
                "raw_host_properties": hostprop_dict
            }
        )
        host.clear()

    return list(sorted(details, key=lambda x: get_host_displayname(
        x['name'], x['ip_address'], x['name'], args.by_ip, args.by_fqdn)))
