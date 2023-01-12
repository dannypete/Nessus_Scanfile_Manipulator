import logging

import xml.etree.ElementTree as ET

from common.utils import get_nessus_hostproperty_by_name

PLUGIN_NAME = __name__.rsplit(".", 1)[1]

logger = logging.getLogger(__name__)

def insert_subparser(subparser):
    arg_parser = subparser.add_parser(PLUGIN_NAME, help="Print information about vulnerabilities present in the Nessus scan file. Default action: print unique")
    arg_parser.set_defaults(handler=handle)
    arg_parser.set_defaults(parser=PLUGIN_NAME)

    mutual_ex_parser = arg_parser.add_mutually_exclusive_group()
    mutual_ex_parser.add_argument("--unique", help="Print unique vulnerabilities (by Finding Name)", action="store_true", default=False)
    mutual_ex_parser.add_argument("--all", help="Print all vulnerabilities", action="store_true", default=False)
    mutual_ex_parser.add_argument("--by-host", help="Print all vulnerabilities grouped by host", action="store_true", default=False)

    mutual_ex_parser2 = arg_parser.add_mutually_exclusive_group()
    mutual_ex_parser2.add_argument("--by-ip", help="Designate hosts by their IP only", action="store_true", default=False)
    mutual_ex_parser2.add_argument("--by-fqdn", help="Designate hosts by FQDN only (falls back to IP no FQDN reported)", action="store_true", default=False)

def handle(args):
    if args.unique:
        res = get_unique_vulns(args)

    elif args.all:
        res = get_all_vulns(args)

    elif args.by_host:
        res = get_vulns_per_host(args)

    else:
        res = get_unique_vulns(args)

    print(res)
    return res

def get_unique_vulns(args):
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
            plugin_id = finding.get("pluginID")
            plugin_name = finding.get("pluginName").replace("\n", "\\n")
            severity = finding.get("severity")

            if plugin_name in res:
                res[plugin_name]["affected_hosts"].add(f"{name}{':' + port if int(port) != 0 else ''}")
                res[plugin_name]["severities"].add(int(severity))
            
            else:
                description = finding.find("description").text.replace("\n", "\\n")
                solution = finding.find("solution").text.replace("\n", "\\n")
                risk = finding.find("risk_factor").text
                plugin_type = finding.find("plugin_type").text
                res[plugin_name] = {
                    "plugin_id": plugin_id,
                    "plugin_type": plugin_type,
                    "description": description,
                    "solution": solution,
                    "risk": risk,
                    "severities": set([int(severity)]),
                    "affected_hosts": set([f"{name}{':' + port if int(port) != 0 else ''}"])
                }

    sorted_keys = sorted(res.keys(), key=lambda x: (-max(res[x]["severities"]), x))
    sorted_res = []
    for k in sorted_keys:
        sorted_res.append(f"Plugin Name: {k}\nSeverities: {sorted(res[k]['severities'], reverse=True)}\nRisk: {res[k]['risk']}\nAffected_Hosts: {','.join(sorted(res[k]['affected_hosts']))}\nDescription: {res[k]['description']}\nSolution: {res[k]['solution']}\nPlugin ID: {res[k]['plugin_id']}\nPlugin Type: {res[k]['plugin_type']}\n")

    return "\n".join(sorted_res)

def get_vulns_per_host(args):
    tree = ET.parse(args.input_file)
    root = tree.getroot()

    res = dict()
    for host in root.iter("ReportHost"):
        hostprops = host.find("HostProperties")
        _ip = get_nessus_hostproperty_by_name(hostprops, "host-ip")
        _fqdn = get_nessus_hostproperty_by_name(hostprops, "host-fqdn", None)
        name = get_host_displayname(_ip, _fqdn, args.by_ip, args.by_fqdn)
        findings = list()
        for finding in host.iter("ReportItem"):
            port = finding.get("port")
            protocol = finding.get("protocol")
            service = finding.get("svc_name")
            plugin_name = finding.get("pluginName").replace("\n", "\\n")
            severity = finding.get("severity")

            findings.append({
                "plugin_name": plugin_name,
                "severity": int(severity),
                "port": int(port),
                "protocol": protocol,
                "service": service
            })
        res[name] = findings

    sorted_host_keys = sorted(res.keys())
    sorted_res = []
    for k in sorted_host_keys:
        sorted_host_findings = sorted(res[k], key=lambda x: (-x["severity"], x["plugin_name"]))
        one_host_res = f"Host: {k}\n"
        for finding in sorted_host_findings:
            one_host_res += f"Severity=\"{finding['severity']}\" Finding=\"{finding['plugin_name']}\" Port=\"{finding['protocol'] + ':' + str(finding['port'])}\" Service=\"{finding['service']}\"\n"
        sorted_res.append(one_host_res)
    
    return "\n".join(sorted_res)

def get_all_vulns(args):
    tree = ET.parse(args.input_file)
    root = tree.getroot()

    res = list()
    for host in root.iter("ReportHost"):
        hostprops = host.find("HostProperties")
        _ip = get_nessus_hostproperty_by_name(hostprops, "host-ip")
        _fqdn = get_nessus_hostproperty_by_name(hostprops, "host-fqdn", None)
        name = get_host_displayname(_ip, _fqdn, args.by_ip, args.by_fqdn)
        for finding in host.iter("ReportItem"):
            port = finding.get("port")
            protocol = finding.get("protocol")
            service = finding.get("svc_name")
            plugin_name = finding.get("pluginName").replace("\n", "\\n")
            severity = finding.get("severity")

            res.append({
                "plugin_name": plugin_name,
                "severity": int(severity),
                "port": int(port),
                "protocol": protocol,
                "service": service,
                "ip": _ip,
                "fqdn": _fqdn,
                "name": name
            })

    sorted_res = sorted(res, key=lambda x: (-x['severity'], x['plugin_name'], x['ip'], x['port']))
    final_res = ""
    for finding in sorted_res:
        final_res += f"Severity=\"{finding['severity']}\" Finding=\"{finding['plugin_name']}\" Host=\"{finding['name']}\" Port=\"{finding['protocol'] + ':' + str(finding['port'])}\" Service=\"{finding['service']}\"\n"

    return final_res

def get_host_displayname(ip, fqdn, by_ip, by_fqdn):
    if by_ip:
        return ip
    elif by_fqdn:
        return fqdn or ip
    return f"{ip} ({fqdn})"