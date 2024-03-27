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

def handle(args):
    res = get_metadata_from_file(args)

    return dumps(res)

def get_metadata_from_file(args):
    res = dict()
    context = get_xml_context_from_file(args, tag=[msn.value for msn in MetadataSectionNames])
    for _, section in context:
        if section.tag == MetadataSectionNames.policy.value:
            print("===TOP LEVEL SCAN POLICY===")
            res[MetadataSectionNames.policy.value] = _parse_policy(section, args)
            print()

        if section.tag == MetadataSectionNames.server_preferences.value:
            print("===SERVER PREFERENCES===")
            res[MetadataSectionNames.server_preferences.value] =_parse_server_preferences(section, args)
            print()

        elif section.tag == MetadataSectionNames.plugins_preferences.value:
            print("===PLUGIN PREFERENCES===")
            res[MetadataSectionNames.plugins_preferences.value] = _parse_plugins_preferences(section, args)
            print()

        elif section.tag == MetadataSectionNames.family_section.value:
            print("===FAMILY SECTION===")
            res[MetadataSectionNames.family_section.value] = _parse_family_selection(section, args)
            print()

        elif section.tag == MetadataSectionNames.individual_plugin_selection.value:
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
        print(f"{preference_name}: {preference_value}")
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

        print(f"Plugin: {plugin_name} (ID: {plugin_id})")
        print(f"Preference Name: {preference_name} (preference type: {preference_type})")
        print(f"Preference Value: {preference_values}")
        print(f"Selected Value: {selected_value}")
        print()
    
    return  plugin_prefs

def _parse_family_selection(ctx, args):
    family_selections = dict()
    for _, family_elem in ET.iterwalk(ctx, tag="FamilyItem"):
        family_name = family_elem.find("FamilyName").text
        status = family_elem.find("status")

        family_selections[family_name] = status
        print(f"{family_name}: {status}")

    return family_selections

def _parser_individual_plugin_selection(ctx, args):
    individual_selections = list()
    for _, indiv_elem in ET.iterwalk(ctx, tag="PluginItem"):
        plugin_id = indiv_elem.find("PluginId").text
        plugin_name = indiv_elem.find("PluginName").text
        plugin_family = indiv_elem.find("Family").text
        status = indiv_elem.find("Status").text

        plugin_dict = dict(
            PluginId=plugin_id,
            PluginName=plugin_name,
            PluginFamily=plugin_family,
            PluginStatus=status            
        )
        individual_selections.append(plugin_dict)

        print(f"Plugin Name: {plugin_name} (ID: {plugin_id}) (family: {plugin_family})")
        print(f"Status: {status}")
        print()

    return individual_selections


