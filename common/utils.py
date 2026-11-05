import logging
import lxml.etree as ET
import sys

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
    for _, tagnode in ET.iterwalk(host_properties_node, tag="tag"):
        if tagnode.get("name") == tag_name:
            return tagnode.text
    return default_result

def get_host_displayname(name, ip, fqdn, by_ip=False, by_fqdn=False):
    if by_ip:
        return ip
    if by_fqdn:
      return fqdn or ip
    return name or fqdn or ip

def get_xml_context_from_file(args, input_file: str = None, tag="ReportHost"):
    if 'input_file' in args:
        return ET.iterparse(source=args.input_file, tag=tag, no_network=True, resolve_entities=False, load_dtd=False)
    elif input_file is not None:
        return ET.iterparse(source=input_file, tag=tag, no_network=True, resolve_entities=False, load_dtd=False)
    elif args.stdin: 
        return ET.iterparse(source=sys.stdin.buffer, tag=tag, no_network=True, resolve_entities=False, load_dtd=False, encoding='utf-8')