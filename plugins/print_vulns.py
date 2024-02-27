import ipaddress
import logging

import lxml.etree as ET
from pprint import pformat

from common.utils import get_nessus_hostproperty_by_name, get_host_displayname, get_xml_context_from_file

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
    mutual_ex_parser.add_argument("--compliance", help="Print CIS benchmark data ONLY (doesn't parse normal findings)", action="store_true", default=False)

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

    elif args.compliance:
        res = get_compliance_vulns(args)

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

            if plugin_name in res:
                res[plugin_name]["affected_hosts"].add(f"{name}{':' + port if int(port) != 0 else ''}")
            
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
                    "severity": int(severity),
                    "affected_hosts": set([f"{name}{':' + port if int(port) != 0 else ''}"])
                }
                finding.clear()
        host.clear()

    sorted_keys = sorted(res.keys(), key=lambda x: (-res[x]["severity"], x))
    sorted_res = []
    for k in sorted_keys:
        if args.by_ip:
            sorted_res.append(f"Plugin Name: {k}\nSeverity: {res[k]['severity']}\nRisk: {res[k]['risk']}\nAffected_Hosts: {','.join(sorted(res[k]['affected_hosts'], key=lambda x: ipaddress.ip_address(x.split(':')[0])))}\nDescription: {res[k]['description']}\nSolution: {res[k]['solution']}\nPlugin ID: {res[k]['plugin_id']}\nPlugin Type: {res[k]['plugin_type']}\n")
        else:
            sorted_res.append(f"Plugin Name: {k}\nSeverity: {res[k]['severity']}\nRisk: {res[k]['risk']}\nAffected_Hosts: {','.join(sorted(res[k]['affected_hosts']))}\nDescription: {res[k]['description']}\nSolution: {res[k]['solution']}\nPlugin ID: {res[k]['plugin_id']}\nPlugin Type: {res[k]['plugin_type']}\n")

    return "\n".join(sorted_res)

def get_vulns_per_host(args):
    res = dict()
    context = get_xml_context_from_file(args, tag="ReportHost")
    for _, host in context:
        hostprops = host.find("HostProperties")
        _ip = get_nessus_hostproperty_by_name(hostprops, "host-ip")
        _fqdn = get_nessus_hostproperty_by_name(hostprops, "host-fqdn", None)
        name = get_host_displayname(_ip, _fqdn, args.by_ip, args.by_fqdn)
        findings = list()
        for _, finding in ET.iterwalk(host, tag="ReportItem"):
            port = finding.get("port")
            protocol = finding.get("protocol")
            service = finding.get("svc_name")
            plugin_name = finding.get("pluginName").replace("\n", "\\n")
            severity = finding.get("severity")

            logger.debug(f"Finding {plugin_name} (severity={severity}) for {name} affecting port {port}")

            findings.append({
                "plugin_name": plugin_name,
                "severity": int(severity),
                "port": int(port),
                "protocol": protocol,
                "service": service
            })
            finding.clear()
        res[name] = findings
        host.clear()

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
    res = list()
    context = get_xml_context_from_file(args, tag="ReportHost")
    for _, host in context:
        hostprops = host.find("HostProperties")
        _ip = get_nessus_hostproperty_by_name(hostprops, "host-ip", None)
        _fqdn = get_nessus_hostproperty_by_name(hostprops, "host-fqdn", None)
        name = get_host_displayname(_ip, _fqdn, args.by_ip, args.by_fqdn)
        if name is None:
            name = host.get("name")
        for _, finding in ET.iterwalk(host, tag="ReportItem"):
            port = finding.get("port")
            protocol = finding.get("protocol")
            service = finding.get("svc_name")
            plugin_name = finding.get("pluginName").replace("\n", "\\n")
            severity = finding.get("severity")
            plugin_output = finding.find("plugin_output").text.replace("\n", "\\n") if finding.find("plugin_output") is not None else ''

            logger.debug(f"Finding {plugin_name} (severity={severity}) for {name} affecting port {port}")

            res.append({
                "plugin_name": plugin_name,
                "severity": int(severity),
                "port": int(port),
                "protocol": protocol,
                "service": service,
                "ip": _ip,
                "fqdn": _fqdn,
                "name": name,
                "plugin_output": plugin_output
            })
            finding.clear()
        host.clear()

    try:
        if args.by_ip:
            sorted_res = sorted(res, key=lambda x: (-x['severity'], x['plugin_name'], ipaddress.ip_address(x['ip']) if x['ip'] is not None else ipaddress.ip_address('1.1.1.1'), x['port']))
        else:
            sorted_res = sorted(res, key=lambda x: (-x['severity'], x['plugin_name'], x['ip'] or x['name'], x['port']))
        final_res = ""
        for finding in sorted_res:
            final_res += f"Severity=\"{finding['severity']}\" Finding=\"{finding['plugin_name']}\" Host=\"{finding['name']}\" Port=\"{finding['protocol'] + ':' + str(finding['port'])}\" Service=\"{finding['service']}\" Plugin_Output=\"{finding['plugin_output']}\"\n"

    except ValueError as e:
        import sys
        print(e)
        sys.exit(-1)

    return final_res

def get_compliance_vulns(args):
    # make sure to do `cat asdf.nessus | sed 's/<cm:/cm__/g | sed 's|</cm:|</cm__|' | nessus_scanfile_parser.py --stdin`
    # or become a big boy and figure out how to make LXML understand XML namespaces

    logger.warn("Before using the --compliance flag, you might consider consolidating the CIS Nessus scan files \
                e.g. by copying all the ReportHosts from various files into one Nessus file.")
    logger.warn("To get this parser to work, you'll want to do `cat CIS_result.nessus | | sed 's/<cm:/<cm__/g' | \
                sed 's|</cm:|</cm__|g' | ./nessus_scanfile_manipulator.py --stdin print_vulns --compliance")

    res = dict()
    context = get_xml_context_from_file(args, tag="ReportHost")
    for _, host in context:
        hostprops = host.find("HostProperties")
        _ip = get_nessus_hostproperty_by_name(hostprops, "host-ip", None)
        _fqdn = get_nessus_hostproperty_by_name(hostprops, "host-fqdn", None)
        name = get_host_displayname(_ip, _fqdn, args.by_ip, args.by_fqdn)
        if name is None:
            name = host.get("name")
        for _, finding in ET.iterwalk(host, tag="ReportItem"):

            plugin_name = finding.get("pluginName")
            plugin_id = finding.get("pluginID")
            severity = int(finding.get("severity"))
            if finding.get("pluginFamily") != "Policy Compliance":
                logger.info(f"Skipping finding named {plugin_name} for host {name}")
                continue
            else:
                logger.debug(f"Processing severity {severity} finding {plugin_name} (ID: {plugin_id}) for host {name}")

            check_name = finding.find("cm__compliance-check-name").text.replace("\n", " ")
            check_result = finding.find("cm__compliance-result").text.replace("\n", " ")
            description = finding.find("cm__compliance-info").text.replace("\n", " ")
            solution = finding.find("cm__compliance-solution").text.replace("\n", " ")
            check_references = finding.find("cm__compliance-reference").text.replace("\n", " ")
            check_see_also = finding.find("cm__compliance-see-also").text.replace("\n", " ")
            check_output = finding.find("cm__compliance-actual-value").text.replace("\n", " ") if finding.find("cm__compliance-actual-value") is not None else None
            instanz = finding.find("cm__compliance-instance").text.replace("\n", " ") if finding.find("cm__compliance-instance") is not None else None
            policy_value = finding.find("cm__compliance-policy-value").text.replace("\n", " ") if finding.find("cm__compliance-policy-value") is not None else None
            error = finding.find("cm__compliance-error").text.replace("\n", " ") if finding.find("cm__compliance-error") is not None else None

            if instanz is not None:
                db = instanz.split("/")[1]
            elif check_output is not None:
                db = check_output.split(":")[0].split("\n")[0]
            elif error is not None:
                db = error.split("/")[1]
            else:
                logger.warn("Couldn't determine DB/SID for current finding")
                db = "BROKEN"

            finding_json = {
                "hostName": name,
                "database": db,
                "instance": instanz,
                "pluginName": plugin_name,
                "pluginId": plugin_id,
                "severity": severity,
                "title": check_name,
                "description": description,
                "solution": solution,
                "checkResult": check_result,
                "pluginOutput": check_output,
                "references": check_references,
                "seeAlso": check_see_also,
                "policyValue": policy_value,
                "error": error
            }

            if check_result.upper() == "PASSED":
                continue

            if finding_json['title'] in res:
                res[finding_json["title"]].append(finding_json)
            else:
                res[finding_json["title"]] = [finding_json]

    # return _format_compliance_output_csv(res)
    # return _format_compliance_output_json(res)
    return _format_compliance_output_text(res)

def _format_compliance_output_text(result_dict: dict):
    logger.log("Outputting compliance parse result as text")
    for i, key in enumerate(sorted(result_dict.keys(), key=lambda v: [int(p) for p in v.split(" ")[0].split('.') if p.isdigit()])):

        print(f"{key}")
        print(f"TITLE: 2.{i+1} {key.split(' ',1)[1].strip()} ({key.split(' ', 1)[0]})")
        print(f"SEVERITY:  {result_dict[key][0]['severity']}")
        print(f"CHECK RESULT:  {result_dict[key][0]['checkResult']}")
        print(f"AFFECTED HOSTS:\n  {' '.join([result_dict[key][i]['hostName'] + '/' + result_dict[key][i]['database'] for i in range(len(result_dict[key]))])}")
        print(f"DESCRIPTION:  {result_dict[key][0]['description']}")
        print(f"EVIDENCE:  {result_dict[key][0]['policyValue']}")
        print(f"PLUGIN OUTPUT:  {result_dict[key][0]['pluginOutput']}")
        print(f"SOLUTION:  {result_dict[key][0]['solution']}")
        print(f"REFERENCES:  {result_dict[key][0]['references']}")
        print(f"SEE ALSO:  {result_dict[key][0]['seeAlso']}")
        print(f"ERROR:  {result_dict[key][0]['error']}")
        print("\n\n\n")

def _format_compliance_output_json(result_dict: dict):
    import json
    logger.log("Outputting compliance parse result as JSON")
    return json.dumps(result_dict)

def _format_compliance_output_csv(result_dict: dict):
    import csv, io
    logger.log("Outputting compliance parse result as CSV")
    flattened = []
    for key in result_dict:
        flattened.extend(result_dict[key])

    f = io.StringIO("")
    writer = csv.DictWriter(f, fieldnames=flattened[0].keys())
    writer.writeheader()
    writer.writerows(flattened)

    return f.getvalue()
