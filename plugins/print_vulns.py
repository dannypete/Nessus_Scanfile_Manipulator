import ipaddress
import logging

import lxml.etree as ET

from common.utils import get_nessus_hostproperty_by_name, get_host_displayname, get_xml_context_from_file

PLUGIN_NAME = __name__.rsplit(".", 1)[1]

logger = logging.getLogger(__name__)

def insert_subparser(subparser):
    arg_parser = subparser.add_parser(PLUGIN_NAME, help="Print information about vulnerabilities present in the Nessus scan file. Default action: print unique")
    arg_parser.set_defaults(handler=handle)
    arg_parser.set_defaults(parser=PLUGIN_NAME)

    mutual_ex_parser = arg_parser.add_mutually_exclusive_group()
    mutual_ex_parser.add_argument("--unique", help="Print unique vulnerabilities (by Finding Name)", 
                                  action="store_true", default=False)
    mutual_ex_parser.add_argument("--all", help="Print all vulnerabilities", 
                                  action="store_true", default=False)
    mutual_ex_parser.add_argument("--by-host", help="Print all vulnerabilities grouped by host", 
                                  action="store_true", default=False)

    mutual_ex_parser2 = arg_parser.add_mutually_exclusive_group()
    mutual_ex_parser2.add_argument("--by-ip", help="Designate hosts by their IP only", 
                                   action="store_true", default=False)
    mutual_ex_parser2.add_argument("--by-fqdn", 
                                   help="Designate hosts by FQDN only (falls back to IP if no FQDN was reported)", 
                                   action="store_true", default=False)

def handle(args):
    if args.unique:
        res = get_unique_vulns(args)

    elif args.all:
        res = get_all_vulns(args)

    elif args.by_host:
        res = get_vulns_per_host(args)

    else:
        res = get_unique_vulns(args)

    if args.debug:
        res += "\n\n\n\t\t!!!!NOTE that severities reported in Nessus are 0 (low) to 4 (high)!!!!\n\n\n"

    print(res)
    return res

def get_unique_vulns(args):
    res = dict()
    context = get_xml_context_from_file(args, tag="ReportHost")
    for _, host in context:
        hostprops = host.find("HostProperties")
        _ip = get_nessus_hostproperty_by_name(hostprops, "host-ip")
        _fqdn = get_nessus_hostproperty_by_name(hostprops, "host-fqdn", None)
        name = _fqdn if (args.by_fqdn and _fqdn is not None) else _ip  # custom behavior here so it is more understandable in the output
        for _, finding in ET.iterwalk(host, tag="ReportItem"):
            port = finding.get("port")
            plugin_id = finding.get("pluginID")
            plugin_name = finding.get("pluginName").replace("\n", "\\n")
            severity = finding.get("severity")

            logger.debug(f"Finding {plugin_name} (severity={severity}, ID={plugin_id}) for {name} affecting port {port}")

            if plugin_id in res:
                res[plugin_id]["affected_hosts"].add(f"{name}{':' + port if int(port) != 0 else ''}")
            
            else:
                description = finding.find("description").text.replace("\n", "\\n")
                solution = finding.find("solution").text.replace("\n", "\\n")
                risk = finding.find("risk_factor").text
                plugin_type = finding.find("plugin_type").text
                res[plugin_id] = {
                    "plugin_name": plugin_name,
                    "plugin_type": plugin_type,
                    "description": description,
                    "solution": solution,
                    "risk": risk,
                    "severity": int(severity),
                    "affected_hosts": set([f"{name}{':' + port if int(port) != 0 else ''}"])
                }
                finding.clear()
        host.clear()

    sorted_keys = sorted(res.keys(), key=lambda x: (-res[x]["severity"], res[x]['plugin_name']))
    sorted_res = []
    for k in sorted_keys:
        if args.by_ip:
            sorted_res.append(
                f"Plugin_Name: {res[k]['plugin_name']}\nSeverity: {res[k]['severity']}\nRisk: {res[k]['risk']}\nAffected_Hosts: {','.join(sorted(res[k]['affected_hosts'], key=lambda x: ipaddress.ip_address(x.split(':')[0])))}\nDescription: {res[k]['description']}\nSolution: {res[k]['solution']}\nPlugin ID: {k}\nPlugin Type: {res[k]['plugin_type']}\n")
        else:
            sorted_res.append(
                f"Plugin_Name: {res[k]['plugin_name']}\nSeverity: {res[k]['severity']}\nRisk: {res[k]['risk']}\nAffected_Hosts: {','.join(sorted(res[k]['affected_hosts']))}\nDescription: {res[k]['description']}\nSolution: {res[k]['solution']}\nPlugin ID: {k}\nPlugin Type: {res[k]['plugin_type']}\n")

    return "\n".join(sorted_res)

def get_vulns_per_host(args):

    vuln_details = _parse_vuln_details(args)

    host_vulns = dict()
    for vuln in vuln_details:

        identifier = None
        if args.by_ip:
            identifier = vuln['ip']
        elif args.by_fqdn:
            identifier = vuln['fqdn'] or vuln['name'] or vuln['ip']
        else:
            identifier = vuln['name'] or vuln['ip']

        if identifier in host_vulns:
            host_vulns[identifier].append(vuln)
        else:
            host_vulns[identifier] = [vuln]

    res = ""
    for host in sorted(host_vulns.keys()):
        res += f"ReportHost: \"{host}\"\n"
        for finding in sorted(host_vulns[host], key=lambda x: (-x['severity'], x['service'], x['port'], x['plugin_name'])):
            res += f"\tSeverity=\"{finding['severity']}\" Finding=\"{finding['plugin_name']}\" ID=\"{finding['plugin_id']}\" Port=\"{finding['protocol'] + ':' + str(finding['port'])}\" Service=\"{finding['service']}\"\n"
        res += "\n"

    return res


def get_all_vulns(args):

    vuln_details = _parse_vuln_details(args)

    if args.by_ip:
        vuln_details = list(sorted(vuln_details, key=lambda x: (-x['severity'], x['plugin_name'], ipaddress.ip_address(x['ip']) if \
                                                    x['ip'] is not None else ipaddress.ip_address('1.1.1.1'), x['port'])))
    elif args.by_fqdn:
        vuln_details = list(sorted(vuln_details, key=lambda x: (-x['severity'], x['plugin_name'], x['ip'] or x['name'], x['port'])))
    else:
        vuln_details = list(sorted(vuln_details, key=lambda x: (-x['severity'], x['plugin_name'], x['name'] or x['ip'], x['port'])))

    res = ""
    for finding in vuln_details:
        res += f"Severity=\"{finding['severity']}\" Finding=\"{finding['plugin_name']}\" ID=\"{finding['plugin_id']}\" Host=\"{finding['name']}\" Port=\"{finding['protocol'] + ':' + str(finding['port'])}\" Service=\"{finding['service']}\" Plugin_Output=\"{finding['plugin_output']}\"\n"

    return res


def _parse_vuln_details(args):

    details = []
    context = get_xml_context_from_file(args, tag="ReportHost")
    for _, host in context:
        hostprops = host.find("HostProperties")

        name = None
        _ip = get_nessus_hostproperty_by_name(hostprops, "host-ip")
        _fqdn = get_nessus_hostproperty_by_name(hostprops, "host-fqdn", None)
        _name = host.get("name", None)
        if args.by_ip:
            name = _ip
        elif args.by_fqdn:
            name = _fqdn or _ip
        else:
            name = _name or _fqdn or _ip

        for _, finding in ET.iterwalk(host, tag="ReportItem"):
            port = finding.get("port")
            protocol = finding.get("protocol")
            service = finding.get("svc_name")
            plugin_name = finding.get("pluginName").replace("\n", "\\n")
            plugin_id = finding.get("pluginID")
            plugin_type = finding.find("plugin_type").text
            risk = finding.find("risk_factor").text
            severity = finding.get("severity")
            plugin_output = finding.find("plugin_output").text.replace("\n", "\\n") if finding.find("plugin_output") is not None else ''

            logger.debug(f"Finding {plugin_name} (severity={severity}) for {name} affecting port {port}")

            details.append(
                {
                    "host_name": name,
                    "host_ip_address": _ip,
                    "host_fqdn": _fqdn,
                    "plugin_id": plugin_id,
                    "plugin_name": plugin_name,
                    "plugin_type": plugin_type,
                    "severity": int(severity),
                    "port": int(port),
                    "protocol": protocol,
                    "service": service,
                    "ip": _ip,
                    "fqdn": _fqdn,
                    "name": name,
                    "plugin_output": plugin_output,
                    "risk": risk,
                }
            )
            finding.clear()
        host.clear()

    return list(sorted(details, key=lambda x: get_host_displayname(
        x['name'], x['ip'], x['name'], args.by_ip, args.by_fqdn)))


