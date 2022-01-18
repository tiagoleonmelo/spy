#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import json
from astree import Node
from pprint import pprint

from logger import Logger

log = Logger.get_logger("spy")

def main(tree, patterns):
    """Main program"""
    #root = Node("", []).parse_dict(tree) # Static access
    #root.print_tree()

    root = Node("", {}).make_child(tree)
    #root.print_tree()
    #root.taint_nodes()

    for pattern in patterns:
        # Get program variables and taint the sources
        root.extract_variables(pattern)
        log.debug("Successfully extracted variables from program")
        
        # Fetch variables program - global state of the program
        variables = root.get_variables()
        log.debug(variables)

        # Traverse tree and taint variables that have been in contact with sources
        root.taint_nodes()
        log.debug(variables)

        # Check if there are any tainted sinks
        

        # Build output
    
    return 0


if __name__ == "__main__":

    if len(sys.argv) != 3:
        log.error(
            "Please provide an AST of the program slice to parse and vulnerability patterns."
        )
        log.error(
            "Usage:\n\tpython main.py <input_slice.json> <vulnerability_patterns.json>\n"
        )
        sys.exit(1)

    with open(sys.argv[1]) as slice_input:
        tree = json.load(slice_input)
    log.debug("Finished parsing tree")

    with open(sys.argv[2]) as pattern_input:
        patterns = json.load(pattern_input)
    log.debug("Finished loading %d vulnerability patterns" % len(patterns))

    main(tree, patterns)