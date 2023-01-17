#!/usr/bin/env python3
import argparse
import logging
import os
import sys

import plugins

PACKAGE_DIRS = [__name__, "plugins", "common"]

logger = logging.getLogger(__name__)

def get_parser():
    argparser = argparse.ArgumentParser()
    argparser.add_argument("--debug", help="Debug output (implies verbose)", required=False, action="store_true", default=False)
    argparser.add_argument("-v", "--verbose", help="More output", required=False, action="store_true", default=False)
    argparser.add_argument("-i", "--input-file", help="Input .nessus file", required=False, type=str, default=None)
    argparser.add_argument("-o", "--output-file", help="Path to write output", required=False, type=str, default=None)
    subparser = argparser.add_subparsers(help="Choose a plugin to use")

    return argparser, subparser

if __name__ == "__main__":
    parser, subparser = get_parser()
    loaded_plugins = plugins.load_plugins(subparser)
    args = parser.parse_args()

    root_handler = logging.StreamHandler()

    if args.debug:
        root_handler.setFormatter(logging.Formatter('[%(levelname)s] %(filename)s:%(lineno)s %(message)s'))
        log_level = logging.DEBUG        
    elif args.verbose:
        root_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
        log_level = logging.INFO        
    else:
        log_level = logging.WARN

    for package in PACKAGE_DIRS:
            package_logger = logging.getLogger(package)
            package_logger.setLevel(log_level)
            package_logger.addHandler(root_handler)

    # TODO check that infile (and outfile, if provided) is readable/writable

    logger.debug(f"Loaded plugins: {[plugin.PLUGIN_NAME for plugin in loaded_plugins]}")
    logger.debug(f"Command-line arguments: {args}")
    
    if not hasattr(args, "handler"):
        logger.error("No plugin was selected.")
        parser.print_help()
        sys.exit(-1)

    result = args.handler(args)
    print(result)

    if args.output_file is not None:
        with open(args.output_file, "w") as out:
            out.write(result)
            logger.info(f"Output written to {os.path.abspath(args.output_file)}")
    else:
        logger.debug("Not saving output to file as no output path was provided.")
