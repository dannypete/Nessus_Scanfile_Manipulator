import ipaddress
import logging

import lxml.etree as ET
from enum import Enum

from common.utils import get_nessus_hostproperty_by_name

PLUGIN_NAME = __name__.rsplit(".", 1)[1]

logger = logging.getLogger(__name__)


class FilterParameters(Enum):
    ip = "host-ip"
    fqdn = "host-fqdn"
    plugin_id = "pluginID"
    partial_title = "plugin_title"
    finding_port = "port"
    finding_service = "svc_name"

    def __str__(self) -> str:
        return self.name

def insert_subparser(subparser):
    arg_parser = subparser.add_parser(PLUGIN_NAME, help="Remove vulns using the provided (CASE INSENSITIVE) filter values")
    arg_parser.set_defaults(handler=handle)
    arg_parser.set_defaults(parser=PLUGIN_NAME)

    arg_parser.add_argument('--remove-by', choices=[fp.name for fp in FilterParameters], help="Comma-separated list of values for the filter to match on", type=str, required=True)
    mutual_ex_parser = arg_parser.add_mutually_exclusive_group(required=True)
    mutual_ex_parser.add_argument("--filter-value", help="Comma-separated list of values for the filter to match on", type=str)
    mutual_ex_parser.add_argument("--filter-value-file", help="Path to file containing newline-separated list of values for the filter to match on", type=str)
    arg_parser.add_argument("--case-sensitive", help="Force alphabet characters in filter values to be case sensitive (default is case insensitive)", required=False, action="store_true")
    arg_parser.add_argument("--negate", help="Negate the filter (i.e. 'only keep findings which match the filter')", required=False, action="store_true")
    arg_parser.add_argument("--dry-run", help="Do a dry run of the removal, printing some information about any entries that would be removed but not actually outputting the result", required=False, action="store_true")

def handle(args):
    tree = ET.parse(args.input_file)
    root = tree.getroot()

    remove_by = [fp.value for fp in FilterParameters if fp.name == args.remove_by][0]
    negate = args.negate
    case_sensitive = args.case_sensitive
    dry_run = args.dry_run

    if case_sensitive and remove_by in (FilterParameters.plugin_id.value, FilterParameters.finding_port.value, FilterParameters.finding_service.value):
        logger.warning(f"'Case sensitive' flag doesn't have any effect on filter type {remove_by}")

    if args.filter_value:
        filter_value_list = args.filter_value.split(",")
    else:
        filter_value_list = open(args.filter_value_file, "r").read().splitlines(keepends=False)

    logger.debug(f"Input filter is: \"Finding {remove_by} {'is' if not negate else 'is NOT'} among {filter_value_list}\" (case-sensitive={case_sensitive})")

    dry_run_res = []
    for host in root.iter("ReportHost"):
        host_name = host.get("name")
        for finding in host.iter("ReportItem"):
            finding_name = finding.get("pluginName")
            finding_port = finding.get("port")
            finding_svc = finding.get("svc_name")
            finding_value = get_finding_value(host, finding, remove_by, None)
            if finding_value is None:
                logger.debug(f"Property of finding titled \"{finding_name}\" for host named \"{host_name}\" not found, therefore there is not a match.")
                continue

            any_match = check_match_in_fvlist(remove_by, filter_value_list, finding_value, case_sensitive, negate)
            if any_match and dry_run:
                msg = f"Finding \"{finding_name}\" (port=\"{finding_port}\", svc=\"{finding_svc}\") for host named \"{host_name}\" would have been removed using provided filter"
                print(msg)
                dry_run_res.append(msg)

            elif any_match:
                finding.getparent().remove(finding)

    if dry_run:
        logger.warning("Not outputting resulting XML because --dry-run flag was used")
        return "\n".join(dry_run_res)
    else:
        result = ET.tostring(root).decode()
        if args.output_file is None:
            print(result)
        else:
            logger.warning("Not stdout-printing the resulting XML since an output file was specified")
        return result
    
def check_match_in_fvlist(remove_by, filter_value_list, finding_value, case_sensitive, negate):
    for fv in filter_value_list:
        values_match = determine_match(remove_by, fv, finding_value, case_sensitive)
        match = values_match if not negate else not values_match
        if match:
            return True
    return False

def determine_match(remove_by, filter_value, finding_value, case_sensitive):
    logger.debug(f"Determining if '{filter_value}' matches '{finding_value}' {'with case-sensitivity' if case_sensitive else ''} with filter logic for {remove_by}.")

    if remove_by == FilterParameters.ip.value:
        values_match = ipaddress.ip_address(finding_value) in ipaddress.ip_network(filter_value, strict=False)
    elif remove_by == FilterParameters.partial_title.value:
        if case_sensitive:
            values_match = filter_value in finding_value
        else:
            values_match = filter_value.lower() in finding_value.lower()
    elif case_sensitive:
        values_match = finding_value == filter_value
    else:
        values_match = finding_value.lower() == filter_value.lower()

    return values_match

def get_finding_value(hostnode, findingnode, remove_by: FilterParameters, default_value=None):
    if remove_by == FilterParameters.ip.value:
        hostproperties_node = hostnode.find("HostProperties")
        return get_nessus_hostproperty_by_name(hostproperties_node, FilterParameters.ip.value, default_value)

    elif remove_by == FilterParameters.fqdn.value:
        hostproperties_node = hostnode.find("HostProperties")
        return get_nessus_hostproperty_by_name(hostproperties_node, FilterParameters.fqdn.value, default_value)

    elif remove_by == FilterParameters.plugin_id.value:
        return findingnode.get("pluginID", default_value)
    
    elif remove_by == FilterParameters.partial_title.value:
        return findingnode.get("pluginName", default_value)

    elif remove_by == FilterParameters.finding_port.value:
        return findingnode.get("port", default_value)
    
    elif remove_by == FilterParameters.finding_service.value:
        return findingnode.get("svc_name", default_value)
