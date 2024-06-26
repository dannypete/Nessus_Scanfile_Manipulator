import ipaddress
import logging

import lxml.etree as ET
from enum import Enum

from common.utils import str_to_bool, get_nessus_hostproperty_by_name, get_xml_context_from_file

PLUGIN_NAME = __name__.rsplit(".", 1)[1]

logger = logging.getLogger(__name__)


class FilterParameters(Enum):
    ip = "host-ip"
    fqdn = "host-fqdn"
    was_credential_scanned = "Credentialed_Scan"
    partial_cpe = "cpe"
    mac_address = "mac-address"
    nb_name = "netbios-name"

    def __str__(self) -> str:
        return self.name

def insert_subparser(subparser):
    arg_parser = subparser.add_parser(PLUGIN_NAME, help="Remove hosts using the provided (CASE INSENSITIVE) filter \
                                      values")
    arg_parser.set_defaults(handler=handle)
    arg_parser.set_defaults(parser=PLUGIN_NAME)

    arg_parser.add_argument('--remove-by', choices=[fp.name for fp in FilterParameters], help="Comma-separated list of \
                            values for the filter to match on. Note \"ip\" allows CIDR notation", 
                            type=str, required=True)
    mutual_ex_parser = arg_parser.add_mutually_exclusive_group(required=True)
    mutual_ex_parser.add_argument("--filter-value", help="Comma-separated list of values for the filter to match on", 
                                  type=str)
    mutual_ex_parser.add_argument("--filter-value-file", help="Path to file containing newline-separated list of \
                                  values for the filter to match on", 
                                  type=str)
    arg_parser.add_argument("--case-sensitive", help="Force alphabet characters in filter values to be case \
                            sensitive (default is case insensitive)", 
                            required=False, action="store_true")
    arg_parser.add_argument("--negate", help="Negate the filter (i.e. 'only keep hosts which match the filter')", 
                            required=False, action="store_true")
    arg_parser.add_argument("--dry-run", help="Do a dry run of the removal, printing some information about any \
                            entries that would be removed but not actually outputting the result", 
                            required=False, action="store_true")

def handle(args):
    remove_by = [fp.value for fp in FilterParameters if fp.name == args.remove_by][0]
    negate = args.negate
    case_sensitive = args.case_sensitive
    dry_run = args.dry_run

    if case_sensitive and remove_by in (FilterParameters.ip.value, FilterParameters.was_credential_scanned.value):
        logger.warning(f"'Case sensitive' flag doesn't have any effect on filter type {remove_by}")

    if args.filter_value:
        filter_value_list = args.filter_value.split(",")
    else:
        filter_value_list = open(args.filter_value_file, "r").read().splitlines(keepends=False)

    logger.debug(f"Input filter is: \"Host {remove_by} {'is' if not negate else 'is NOT'} among {filter_value_list}\" (case-sensitive={case_sensitive})")

    context = get_xml_context_from_file(args, tag="ReportHost")
    dry_run_res = []
    for _, host in context:
        host_name = host.get("name")
        host_value = parse_nessus_host_value(host, remove_by)

        if host_value is None:
            logger.debug(f"HostProperty tag named \"{remove_by}\" not found for host named \"{host_name}\", therefore there is not a match.")
            continue

        if negate:
            any_match = check_hostvalue_in_fvlist_negate(remove_by, filter_value_list, host_value, case_sensitive)
        else:
            any_match = check_hostvalue_in_fvlist(remove_by, filter_value_list, host_value, case_sensitive)

        if any_match and dry_run:
            hostproperties_node = host.find("HostProperties")
            cpe = get_nessus_hostproperty_by_name(hostproperties_node, FilterParameters.partial_cpe.value, 
                                                  "None Reported")
            rdns = get_nessus_hostproperty_by_name(hostproperties_node, "host-rdns", "None Reported")
            msg = f"Host named \"{host_name}\" (primary CPE='{cpe}';  RDNS='{rdns}') would have been removed using provided filter"
            print(msg)
            dry_run_res.append(msg)

        elif any_match:
            host.getparent().remove(host)

    if dry_run:
        logger.warning("Not outputting resulting XML because --dry-run flag was used")
        return "\n".join(dry_run_res)
    else:
        result = ET.tostring(context.root).decode()
        if args.output_file is None:
            print(result)
        else:
            logger.warning("Not stdout-printing the resulting XML since an output file was specified")
        return result

def check_hostvalue_in_fvlist(remove_by, filter_value_list, host_value, case_sensitive):
    for fv in filter_value_list:
        values_match = determine_match(remove_by, fv, host_value, case_sensitive)

        if values_match:
            logger.debug(f"Final match determination: match={values_match} for: {host_value} matches filter value {fv}")
            return True
        
    return False

def check_hostvalue_in_fvlist_negate(remove_by, filter_value_list, host_value, case_sensitive):
    for fv in filter_value_list:
        values_match = determine_match(remove_by, fv, host_value, case_sensitive)

        if values_match:
            logger.debug(f"{host_value} matches filter value, and we're negating, so we want to keep this item")
            return False
        
    return True

def determine_match(remove_by, filter_value, host_value, case_sensitive):
    logger.debug(f"Determining if '{host_value}' {'(with case-sensitivity) ' if case_sensitive else ''}matches filter value '{filter_value}' with filter logic for {remove_by}.")

    if remove_by == FilterParameters.ip.value:
            values_match = ipaddress.ip_address(host_value) in ipaddress.ip_network(filter_value, strict=False)
    elif remove_by == FilterParameters.partial_cpe.value:
        if case_sensitive:
            values_match = filter_value in host_value
        else:
            values_match = filter_value.lower() in host_value.lower() 
    elif remove_by == FilterParameters.was_credential_scanned.value:
        values_match = str_to_bool(host_value) == str_to_bool(filter_value)
    elif case_sensitive:    
        values_match = host_value == filter_value
    else:
        values_match = host_value.lower() == filter_value.lower()

    logger.debug(f"Determined that '{filter_value}' preliminarily {'does' if values_match else 'does not'} match the provided filter")
    return values_match
    
def parse_nessus_host_value(hostnode, remove_by):
    if remove_by == FilterParameters.partial_cpe.value:
        host_value = [tag.text for _,tag in ET.iterwalk(hostnode.find("HostProperties"), tag="tag") if \
                      tag.get("name").startswith(remove_by)]
        host_value = ",".join(host_value) or None
    else:
        host_value = get_nessus_hostproperty_by_name(hostnode.find("HostProperties"), remove_by, None)
    
    logger.debug(f"Parsed host value from the scan file: {host_value}")
    return host_value
