import ipaddress
import logging

import xml.etree.ElementTree as ET
from enum import Enum

from common.utils import strtobool, get_nessus_hostproperty_by_name

PLUGIN_NAME = __name__.rsplit(".", 1)[1]

logger = logging.getLogger(__name__)


class FilterParameters(Enum):
    ip = "host-ip"
    was_credential_scanned = "Credentialed_Scan"
    cpe = "cpe"
    os = "operating-system"
    mac_address = "mac-address"
    nb_name = "netbios-name"

    def __str__(self) -> str:
        return self.name

def insert_subparser(subparser):
    arg_parser = subparser.add_parser(PLUGIN_NAME, help="Remove hosts using the provided (CASE INSENSITIVE) filter values")
    arg_parser.set_defaults(handler=handle)
    arg_parser.set_defaults(parser=PLUGIN_NAME)

    arg_parser.add_argument('--remove-by', choices=[fp.name for fp in FilterParameters], help="Comma-separated list of values for the filter to match on", type=str, required=True)
    mutual_ex_parser = arg_parser.add_mutually_exclusive_group(required=True)
    mutual_ex_parser.add_argument("--filter-value", help="Comma-separated list of values for the filter to match on", type=str)
    mutual_ex_parser.add_argument("--filter-value-file", help="Path to file containing newline-separated list of values for the filter to match on", type=str)
    arg_parser.add_argument("--full-match", help="Look for full matches (less case sensitivity)", required=False, action="store_true")
    arg_parser.add_argument("--case-sensitive", help="Force alphabet characters in filter values to be case sensitive (default is case insensitive)", required=False, action="store_true")
    arg_parser.add_argument("--negate", help="Negate the filter (i.e. 'only keep hosts which match the filter')", required=False, action="store_true")
    arg_parser.add_argument("--dry-run", help="Do a dry run of the removal, printing some information about any entries that would be removed but not actually outputting the result", required=False, action="store_true")

def handle(args):
    tree = ET.parse(args.input_file)
    root = tree.getroot()

    remove_by = [fp.value for fp in FilterParameters if fp.name == args.remove_by][0]
    negate = args.negate
    case_sensitive = args.case_sensitive
    full_match = args.full_match
    dry_run = args.dry_run
    if args.filter_value:
        filter_value_list = args.filter_value.split(",")
    else:
        filter_value_list = open(args.filter_value_file, "r").read().splitlines(keepends=False)

    logger.debug(f"Input filter is: \"Host {remove_by} {'is' if not negate else 'is NOT'} among {filter_value_list}\" (full-match={full_match}, case-sensitive={case_sensitive})")

    dry_run_res = []
    for host in root.iter("ReportHost"):
        host_name = host.get("name")
        host_value = parse_nessus_host_value(host, remove_by)

        if host_value is None:
            logger.debug(f"HostProperty tag named \"{remove_by}\" not found for host named \"{host_name}\", therefore there is not a match.")
            continue

        for fv in filter_value_list:
            values_match = determine_match(remove_by, fv, host_value, case_sensitive, full_match)
            match = values_match if not negate else not values_match
            if dry_run and match:
                hostproperties_node = host.find("HostProperties")
                cpe = get_nessus_hostproperty_by_name(hostproperties_node, FilterParameters.cpe.value, "None Reported")
                rdns = get_nessus_hostproperty_by_name(hostproperties_node, "host-rdns", "None Reported")
                msg = f"Host named \"{host_name}\" (primary CPE='{cpe}';  RDNS='{rdns}') would have been removed using provided filter"
                print(msg)
                dry_run_res.append(msg)

            elif match:
                parent = root.find("Report")
                parent.remove(host)

    if dry_run:
        logger.debug("Not outputting resulting XML because --dry-run flag was used")
        return "\n".join(dry_run_res)
    else:
        newroot = ET.ElementTree(root)
        result = ET.tostring(newroot.getroot(), encoding='unicode')
        if args.output_file:
            logger.warn("Not stdout-printing the resulting XML result since an output file was specified")
        else: 
            print(result)
        return result

def determine_match(remove_by, filter_value, host_value, case_sensitive, full_match):
    logger.debug(f"Determining if '{host_value}' {'fully matches' if full_match else 'partially matches'} '{filter_value}' {'with case-sensitivity' if case_sensitive else ''} with filter logic for {remove_by}.")
    if full_match:
        if remove_by == FilterParameters.ip.value:
            logger.warn("'Full match' and/or 'case sensitive' flags don't have any effect on IP filters")
            values_match = ipaddress.ip_network(host_value, strict=False) == ipaddress.ip_network(filter_value)
        elif remove_by == FilterParameters.was_credential_scanned.value:
            logger.warn("'Full match' and/or 'case sensitive' flags don't have any effect on bool-valued filters")
            values_match = strtobool(host_value) == strtobool(filter_value)
        elif case_sensitive:
            values_match = host_value == filter_value
        else:
            values_match = host_value.lower() == filter_value.lower()

    else:
        if remove_by == FilterParameters.ip.value:
            values_match = ipaddress.ip_network(host_value, strict=False) in ipaddress.ip_network(filter_value)
        elif remove_by == FilterParameters.was_credential_scanned.value:
            values_match = strtobool(host_value) == strtobool(filter_value)
        elif case_sensitive: 
            values_match = filter_value in host_value 
        else:
            values_match = filter_value.lower() in host_value.lower()

    return values_match
    
def parse_nessus_host_value(hostnode, remove_by):
    if remove_by == FilterParameters.cpe.value:
        host_value = [tag.text for tag in hostnode.find("HostProperties").findall("tag") if tag.get("name").startswith(remove_by)]
        if len(host_value) == 0:
            host_value = None
        host_value = ",".join(host_value)
    else:
        host_value = get_nessus_hostproperty_by_name(hostnode.find("HostProperties"), remove_by)
    
    logger.debug(f"Parsed host value from the scan file: {host_value}")
    return host_value