# TODO ITEMS
# list all hosts
# list hosts by subnet / total hosts / using filters?
# list each host with respective found open ports
# list hosts in scan file that are also in input ranges.txt file
# list hosts in scan file that are not in input ranges.txt file
# list hosts in scan file that are also in input exceptions.txt file
# list hosts in scan file that are not in exceptions.txt file (least useful tbh)


# replace "hosts" with "vulns for hosts" in above list
# replace "list hosts" with "remove hosts" in above list


# create .nessus file which just has hosts+respective open ports, e.g.:
# take a file where each line is IP:port (e.g. 10.0.0.0:80) and results in an entry in output .nessus file

import importlib
import logging
import pkgutil


logger = logging.Logger(__name__)


def load_plugins(subparser):
    plugins = []
    for _, name, ispkg in pkgutil.iter_modules(__path__):
            if not ispkg:
                plugin_module = importlib.import_module(__name__ + "." + name)
                plugin_module.insert_subparser(subparser)
                plugins.append(plugin_module)
    return plugins