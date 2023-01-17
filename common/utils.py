import logging

logger = logging.getLogger(__name__)


def str_to_bool(val: str) -> bool:
    val = val.lower()
    if val in ['y', 'yes', 't', 'true', 'on', '1']:
        return True
    elif val in ['n', 'no', 'f', 'false', 'off', '0']:
        return False
    else:
        raise ValueError

def get_nessus_hostproperty_by_name(host_properties_node, tag_name, default_result=None):
    relevant_tag = [tag.text for tag in host_properties_node.findall("tag") if tag_name == tag.get("name")]
    if len(relevant_tag) == 0:
        return default_result
    elif len(relevant_tag) > 1:
        raise ValueError
    
    return relevant_tag[0]

def get_host_displayname(ip, fqdn, by_ip=False, by_fqdn=False):
    if by_ip:
        return ip
    elif by_fqdn:
        if fqdn is None:
            logger.debug(f"User requested host FQDN designation, but host {ip} did not have a FQDN. Falling back to its IP")
            return ip
        return fqdn
    return f"{ip} ({fqdn or 'No FQDN'})"