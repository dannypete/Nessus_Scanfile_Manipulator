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

    vuln_details = _parse_vuln_details(args)

    vulns_by_id = dict()
    for finding in vuln_details:

        name = finding['host_name']

        port = finding.get('port')
        socket_addr = name + (f':{port}' if port != 0 else '')

        if finding['plugin_id'] in vulns_by_id:
            vulns_by_id[finding['plugin_id']]['affected_hosts'].add(socket_addr)

        else:
            vulns_by_id[finding['plugin_id']] = {
                "plugin_name": finding['plugin_name'],
                "plugin_type": finding['plugin_type'],
                "description": finding['description'],
                "solution": finding['solution'],
                "risk": finding['risk'],
                "severity": int(finding['severity']),
                "affected_hosts": set([socket_addr])
            }

    sorted_keys = sorted(vulns_by_id.keys(), key=lambda x: (-vulns_by_id[x]["severity"], vulns_by_id[x]['plugin_name']))
    sorted_res = []
    for k in sorted_keys:
        if args.by_ip:
            sorted_res.append(
                f"Plugin_Name: {vulns_by_id[k]['plugin_name']}\nSeverity: {vulns_by_id[k]['severity']}\nRisk: {vulns_by_id[k]['risk']}\nAffected_Hosts: {','.join(sorted(vulns_by_id[k]['affected_hosts'], key=lambda x: ipaddress.ip_address(x.split(':')[0])))}\nDescription: {vulns_by_id[k]['description']}\nSolution: {vulns_by_id[k]['solution']}\nPlugin ID: {k}\nPlugin Type: {vulns_by_id[k]['plugin_type']}\n")
        else:
            sorted_res.append(
                f"Plugin_Name: {vulns_by_id[k]['plugin_name']}\nSeverity: {vulns_by_id[k]['severity']}\nRisk: {vulns_by_id[k]['risk']}\nAffected_Hosts: {','.join(sorted(vulns_by_id[k]['affected_hosts']))}\nDescription: {vulns_by_id[k]['description']}\nSolution: {vulns_by_id[k]['solution']}\nPlugin ID: {k}\nPlugin Type: {vulns_by_id[k]['plugin_type']}\n")

    return "\n".join(sorted_res)

def get_vulns_per_host(args):

    vuln_details = _parse_vuln_details(args)

    host_vulns = dict()
    for vuln in vuln_details:

        identifier = vuln['host_name']
        
        if identifier in host_vulns:
            host_vulns[identifier].append(vuln)
        else:
            host_vulns[identifier] = [vuln]

    res = ""
    for host in sorted(host_vulns.keys()):  # TODO sorts IPs naively, not correctly
        res += f"ReportHost: \"{host}\"\n"
        for finding in sorted(host_vulns[host], key=lambda x: (-x['severity'], x['service'], x['port'], x['plugin_name'])):
            res += f"\tSeverity=\"{finding['severity']}\" Finding=\"{finding['plugin_name']}\" ID=\"{finding['plugin_id']}\" Port=\"{finding['protocol'] + ':' + str(finding['port'])}\" Service=\"{finding['service']}\"\n"
        res += "\n"

    return res


def get_all_vulns(args):

    vuln_details = _parse_vuln_details(args)

    if args.by_ip:
        vuln_details = list(sorted(vuln_details, key=lambda x: (-x['severity'], x['plugin_name'], ipaddress.ip_address(x['ip']), x['port'])))
    else:
        vuln_details = list(sorted(vuln_details, key=lambda x: (-x['severity'], x['plugin_name'], x['host_name'], x['port'])))

    res = ""
    for finding in vuln_details:
        res += f"Severity=\"{finding['severity']}\" Finding=\"{finding['plugin_name']}\" ID=\"{finding['plugin_id']}\" Host=\"{finding['host_name']}\" Port=\"{finding['protocol'] + ':' + str(finding['port'])}\" Service=\"{finding['service']}\" Plugin_Output=\"{finding['plugin_output']}\"\n"

    return res


def _parse_vuln_details(args):

    details = []
    context = get_xml_context_from_file(args, tag="ReportHost")
    for _, host in context:
        hostprops = host.find("HostProperties")

        _ip = get_nessus_hostproperty_by_name(hostprops, "host-ip")
        _fqdn = get_nessus_hostproperty_by_name(hostprops, "host-fqdn", None)
        _name = host.get("name", None)

        name = get_host_displayname(_name, _ip, _fqdn, args.by_ip, args.by_fqdn)

        for _, finding in ET.iterwalk(host, tag="ReportItem"):
            port = finding.get("port")
            protocol = finding.get("protocol")
            service = finding.get("svc_name")
            plugin_name = finding.get("pluginName").replace("\n", "\\n")
            plugin_id = finding.get("pluginID")
            plugin_type = finding.find("plugin_type").text
            risk = finding.find("risk_factor").text
            severity = finding.get("severity")
            description = finding.get("description")
            solution = finding.get("solution")
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
                    "description": description,
                    "solution": solution,
                    "port": int(port),
                    "protocol": protocol,
                    "service": service,
                    "ip": _ip,
                    "fqdn": _fqdn,
                    "reported_name": _name,
                    "plugin_output": plugin_output,
                    "risk": risk,
                }
            )
            finding.clear()
        host.clear()

    return list(sorted(details, key=lambda x: get_host_displayname(
        x['reported_name'], x['ip'], x['fqdn'], args.by_ip, args.by_fqdn)))


