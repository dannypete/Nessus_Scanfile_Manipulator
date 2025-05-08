import logging
import lxml.etree as ET

from common.utils import get_nessus_hostproperty_by_name, get_host_displayname, get_xml_context_from_file

PLUGIN_NAME = __name__.rsplit(".", 1)[1]

logger = logging.getLogger(__name__)

COMPLIANCE_NS_URL = '{http://www.nessus.org/cm}'

def insert_subparser(subparser):
    arg_parser = subparser.add_parser(PLUGIN_NAME, help="Print information about CIS benchmark findings present in the \
                                      scan file.")
    arg_parser.set_defaults(handler=handle)
    arg_parser.set_defaults(parser=PLUGIN_NAME)

    mutual_ex_parser = arg_parser.add_mutually_exclusive_group()
    mutual_ex_parser.add_argument("--output-as-text", "-oT", help="Output result as text (the default)", 
                                  action="store_true", default=False)
    mutual_ex_parser.add_argument("--output-as-csv", "-oC", help="Output result as CSV", 
                                  action="store_true", default=False)
    mutual_ex_parser.add_argument("--output-as-json", "-oJ", help="Output result as JSON", 
                                  action="store_true", default=False)

    mutual_ex_parser2 = arg_parser.add_mutually_exclusive_group()
    mutual_ex_parser2.add_argument("--by-ip", help="Designate hosts by their IP only", 
                                   action="store_true", default=False)
    mutual_ex_parser2.add_argument("--by-fqdn", 
                                   help="Designate hosts by FQDN only (falls back to IP if no FQDN is reported)", 
                                   action="store_true", default=False)

def handle(args):
    res = get_compliance_vulns(args)

    if args.output_as_json:
        res = _format_compliance_output_json(res, should_print=True if args.output_file is None else False)

    elif args.output_as_csv:
        res = _format_compliance_output_csv(res, should_print=True if args.output_file is None else False)

    else:
        res = _format_compliance_output_text(res)

    return res

def get_compliance_vulns(args):
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
            is_compliance = finding.find("compliance")
            if finding.get("pluginFamily") != "Policy Compliance" or not is_compliance is not None:
                logger.info(f"Skipping finding named {plugin_name} for host {name}")
                continue
            else:
                logger.debug(f"Processing severity {severity} finding {plugin_name} (ID: {plugin_id}) for host {name}")

            check_name = finding.find(f"{COMPLIANCE_NS_URL}compliance-check-name").text.replace("\n", " ")
            check_result = finding.find(f"{COMPLIANCE_NS_URL}compliance-result").text.replace("\n", " ")
            description = finding.find(f"{COMPLIANCE_NS_URL}compliance-info").text.replace("\n", " ")
            solution = finding.find(f"{COMPLIANCE_NS_URL}compliance-solution").text.replace("\n", " ")
            check_references = finding.find(f"{COMPLIANCE_NS_URL}compliance-reference").text.replace("\n", " ")
            check_see_also = finding.find(f"{COMPLIANCE_NS_URL}compliance-see-also").text.replace("\n", " ")
            check_output = finding.find(f"{COMPLIANCE_NS_URL}compliance-actual-value").text.replace("\n", " ") if \
                finding.find(f"{COMPLIANCE_NS_URL}compliance-actual-value") is not None else None
            instanz = finding.find(f"{COMPLIANCE_NS_URL}compliance-instance").text.replace("\n", " ") if \
                finding.find(f"{COMPLIANCE_NS_URL}compliance-instance") is not None else None
            policy_value = finding.find(f"{COMPLIANCE_NS_URL}compliance-policy-value").text.replace("\n", " ") \
                if finding.find(f"{COMPLIANCE_NS_URL}compliance-policy-value") is not None else None
            error = finding.find(f"{COMPLIANCE_NS_URL}compliance-error").text.replace("\n", " ") \
                if finding.find(f"{COMPLIANCE_NS_URL}compliance-error") is not None else None

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

    return res

def _format_compliance_output_text(result_dict: dict):
    logger.info("Outputting compliance parse result as text")
    for i, key in enumerate(sorted(result_dict.keys(), key=lambda v: [int(p) for p in v.split(" ")[0].split('.') if \
                                                                      p.isdigit()])):

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

def _format_compliance_output_json(result_dict: dict, should_print: bool):
    import json
    logger.info("Outputting compliance parse result as JSON")
    res = json.dumps(result_dict)
    if should_print:
        print(res)
    return res

def _format_compliance_output_csv(result_dict: dict, should_print: bool):
    import csv, io
    logger.info("Outputting compliance parse result as CSV")
    flattened = []
    for key in result_dict:
        flattened.extend(result_dict[key])

    with io.StringIO("") as f: 
        writer = csv.DictWriter(f, fieldnames=flattened[0].keys())
        writer.writeheader()
        writer.writerows(flattened)
        res = f.getvalue()
        
    if should_print:
        print(res)

    return res
