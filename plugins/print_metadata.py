import logging
import lxml.etree as ET
from enum import Enum
from json import dumps

from common.utils import get_xml_context_from_file

PLUGIN_NAME = __name__.rsplit(".", 1)[1]

logger = logging.getLogger(__name__)

class MetadataSectionNames(Enum):
    policy = "Policy"
    server_preferences = "ServerPreferences"
    plugins_preferences = "PluginsPreferences"
    family_section = "FamilySelection"
    individual_plugin_selection = "IndividualPluginSelection"

    def __str__(self) -> str:
        return self.name


def insert_subparser(subparser):
    arg_parser = subparser.add_parser(PLUGIN_NAME, help="Print metadata about the scan as reported in the scan file.")
    arg_parser.set_defaults(handler=handle)
    arg_parser.set_defaults(parser=PLUGIN_NAME)

    arg_parser.add_argument("--no-scan-policy", "-nspo", help="Exclude Scan Policy section", default=False, action="store_true")
    arg_parser.add_argument("--no-server-preferences", "-nspr", help="Exclude Server Preferences section", default=False, action="store_true")
    arg_parser.add_argument("--no-plugin-preferences", "-nppr", help="Exclude Plugin Preferences section", default=False, action="store_true")
    arg_parser.add_argument("--no-family-section", "-nfse", help="Exclude Family Section", default=False, action="store_true")
    arg_parser.add_argument("--no-indiv-plugin-section", "-nips", help="Exclude Individual Plugin Section", default=False, action="store_true")

def handle(args):
    res = get_metadata_from_file(args)

    return dumps(res)

def get_metadata_from_file(args):
    res = dict()
    context = get_xml_context_from_file(args, tag=[msn.value for msn in MetadataSectionNames])
    for _, section in context:
        if not args.no_scan_policy and section.tag == MetadataSectionNames.policy.value:
            print("===TOP LEVEL SCAN POLICY===")
            res[MetadataSectionNames.policy.value] = _parse_policy(section, args)
            print()

        elif not args.no_server_preferences and section.tag == MetadataSectionNames.server_preferences.value:
            print("===SERVER PREFERENCES===")
            res[MetadataSectionNames.server_preferences.value] =_parse_server_preferences(section, args)
            print()

        elif not args.no_plugin_preferences and section.tag == MetadataSectionNames.plugins_preferences.value:
            print("===PLUGIN PREFERENCES===")
            res[MetadataSectionNames.plugins_preferences.value] = _parse_plugins_preferences(section, args)
            print()

        elif not args.no_family_section and section.tag == MetadataSectionNames.family_section.value:
            print("===FAMILY SECTION===")
            res[MetadataSectionNames.family_section.value] = _parse_family_selection(section, args)
            print()

        elif not args.no_indiv_plugin_section and section.tag == MetadataSectionNames.individual_plugin_selection.value:
            print("===INDIVIDUAL PLUGIN SELECTION===")
            res[MetadataSectionNames.individual_plugin_selection.value] = _parser_individual_plugin_selection(section, args)
            print()
            
    return res

def _parse_policy(ctx, args):
    policy_name = ctx.find("policyName").text
    print(policy_name)
    return policy_name

def _parse_server_preferences(ctx, args):
    server_prefs = dict()
    for _, preference_elem in ET.iterwalk(ctx, tag="preference"):
        preference_name = preference_elem.find("name").text
        preference_value = preference_elem.find("value").text
        server_prefs[preference_name] = preference_value

    for k in sorted(server_prefs, key=lambda x: x.lower()):
        print(f"{k}: {server_prefs[k]}")

    return server_prefs

def _parse_plugins_preferences(ctx, args):
    plugin_prefs = list()
    for _, item_elem in ET.iterwalk(ctx, tag="item"):
        plugin_name = item_elem.find("pluginName").text
        plugin_id = item_elem.find("pluginId").text
        fullname = item_elem.find("fullName").text
        preference_name = item_elem.find("preferenceName").text
        preference_type = item_elem.find("preferenceType").text
        preference_values = item_elem.find("preferenceValues").text
        selected_value = item_elem.find("selectedValue").text

        item_dict = dict(
            pluginName=plugin_name,
            pluginId=plugin_id,
            fullName=fullname,
            preferenceName=preference_name,
            preferenceType=preference_type,
            preferenceValues=preference_values,
            selectedValue=selected_value
        )
        plugin_prefs.append(item_dict)

    for pp in sorted(plugin_prefs, key=lambda x: x['pluginName']):
        print(f"Plugin: {pp['pluginName']} (ID: {pp['pluginId']})")
        print(f"Preference Name: {pp['preferenceName']} (preference type: {pp['preferenceType']})")
        print(f"Preference Value: {pp['preferenceValues']}")
        print(f"Selected Value: {pp['selectedValue']}")
        print()
    
    return  plugin_prefs

def _parse_family_selection(ctx, args):
    family_selections = dict()
    for _, family_elem in ET.iterwalk(ctx, tag="FamilyItem"):
        family_name = family_elem.find("FamilyName").text
        status = family_elem.find("status")
        family_selections[family_name] = status

    for k in sorted(family_selections, key=lambda x: x.lower()):
        print(f"{k}: {family_selections[k]}")

    return family_selections

def _parser_individual_plugin_selection(ctx, args):
    individual_selections = list()
    for _, indiv_elem in ET.iterwalk(ctx, tag="PluginItem"):
        plugin_id = indiv_elem.find("PluginId").text
        plugin_name = indiv_elem.find("PluginName").text
        plugin_family = indiv_elem.find("Family").text
        status = indiv_elem.find("Status").text

        plugin_dict = dict(
            pluginId=plugin_id,
            pluginName=plugin_name,
            pluginFamily=plugin_family,
            pluginStatus=status            
        )
        individual_selections.append(plugin_dict)

    for iSection in sorted(individual_selections, key=lambda x: x['pluginName']):
        print(f"Plugin Name: {iSection['pluginName']} (ID: {iSection['pluginId']}) (family: {iSection['pluginFamily']})")
        print(f"Status: {iSection['pluginStatus']}")
        print()

    return individual_selections


