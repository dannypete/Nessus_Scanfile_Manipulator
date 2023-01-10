import ipaddress
import logging
import sys

import xml.etree.ElementTree as ET

PLUGIN_NAME = __name__.rsplit(".", 1)[1]

logger = logging.getLogger(__name__)


def insert_subparser(subparser):
    arg_parser = subparser.add_parser(PLUGIN_NAME, help="Print information about hosts present in the Nessus scan file")
    arg_parser.set_defaults(handler=handle)
    arg_parser.set_defaults(parser=PLUGIN_NAME)

    mutual_ex_parser = arg_parser.add_mutually_exclusive_group()
    mutual_ex_parser.add_argument("--print-host-details", help="Print data about each host", action="store_true")
    mutual_ex_parser.add_argument("--socket-addrs", help="Print all socket addresses (i.e. \"10.20.30.40:8080\")", action="store_true")
    mutual_ex_parser.add_argument("--host-ports", help="Print open ports per host (e.g. \"10.20.30.40: 443,8080\")", action="store_true")

def handle(args):
    if args.print_host_details:
        res = get_host_details(args)

    if args.socket_addrs:
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
        ip = host.get("name")
        tags = dict()
        for tag in host.find("HostProperties"):
            tags[tag.get("name").title()] = tag.text
        host_res = f"Report Host Name: {ip}\n"
        for k in sorted(tags.keys()):
            host_res += f"\t{k}: {tags[k]}\n"
        res["ip"] = host_res

    sorted_res = [res[k] for k in sorted(res.keys(), key=lambda x: ipaddress.ip_address(ip))]
    return "\n".join(sorted_res)

def get_socket_addresses(args):
    tree = ET.parse(args.input_file)
    root = tree.getroot()

    res = set()
    for host in root.iter("ReportHost"):
        ip = host.get("name")
        for finding in host.iter("ReportItem"):
            port = finding.get("port")
            if int(port) == 0:
                plugin_name = finding.get("pluginName")
                logger.debug(f"Finding \"{plugin_name}\" does not have a port. Skipping it.")
                continue
            
            res.add(f"{ip}:{port}")

    sorted_res = sorted(res, key=lambda x: (ipaddress.ip_address(x.split(":")[0]), int(x.split(":")[1])))

    return "\n".join(sorted_res)

def get_ports_by_host(args):
    tree = ET.parse(args.input_file)
    root = tree.getroot()

    res = dict()
    for host in root.iter("ReportHost"):
        ip = host.get("name")
        for finding in host.iter("ReportItem"):
            port = finding.get("port")
            protocol = finding.get("protocol")
            if int(port) == 0:
                plugin_name = finding.get("pluginName")
                logger.debug(f"Finding \"{plugin_name}\" does not have a port. Skipping it.")
                continue
        
            if ip in res:
                res[ip].add(f"{protocol.upper()}/{port}")

            else:
                res[ip] = {f"{protocol.upper()}/{port}"}

    sorted_keys = sorted(res.keys(), key=lambda x: ipaddress.ip_address(x))
    sorted_res = []
    for k in sorted_keys:
        sorted_ports = sorted(res[k], key=lambda x: int(x.split("/")[1]))
        sorted_res.append(f"{k}\t{','.join(sorted_ports)}")

    return "\n".join(sorted_res)

def get_vuln_count_by_socket_address(args):
    pass

def get_vuln_count_by_host(args):
    pass

