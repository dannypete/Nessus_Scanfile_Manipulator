#!/usr/bin/env python3
import argparse
import logging
import os
import sys

from common.db import init_db, insert_scan_details

PACKAGE_DIRS = [__name__, "plugins", "common"]

logger = logging.getLogger(__name__)

def get_parser():
    argparser = argparse.ArgumentParser()
    argparser.add_argument("--debug", help="Debug output (implies verbose)", required=False, 
                           action="store_true", default=False)
    # argparser.add_argument("-v", "--verbose", help="More output", required=False, action="store_true", default=False)
    argparser.add_argument("--sql-file", help="File path to SQLite database file to use. A new one will " \
                           "be created if it does not exist", required=True, type=str)

    argparser.add_argument("nessus_files", help="Input Nessus .nessus file(s)", nargs="+")

    return argparser

if __name__ == "__main__":
    parser = get_parser()
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

    l = logging.getLogger(__name__)
    l.setLevel(log_level)
    l.addHandler(root_handler)

    logger.debug(f"Args: {args}")

    init_db(url=args.sql_file, echo=args.debug)

    logger.debug("DB init completed")

    for f in args.nessus_files:
        logger.debug(f"Inserting into DB file '{f}'")
        insert_scan_details(args, input_file=f)
