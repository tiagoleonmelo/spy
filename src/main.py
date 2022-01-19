#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import json
from pprint import pprint

from astree import Node
from logger import Logger

log = Logger.get_logger("spy")


def check_any_tainted_sinks(vars, pat):
    """Given the final state of a tree traversal and a pattern, checks which sinks have been tainted.
    Returns a list of dictionaries for every vulnerability found"""

    vulns = []

    for sink in pat["sinks"]:
        if vars[sink]:
            # For each tainted sink create 1 vuln
            log.debug("Sink %s tainted by %s" % (sink, vars[sink][0]))

            # Getting source that tainted the sink from variables might be ass if the lists have more than 1 element? vvvv
            # The chains are built by appending to the end, hopefully the first element will always be the source
            vuln = {
                "vulnerability": pat["vulnerability"] + str(len(vulns) + 1),
                "source": vars[sink][0],
                "sink": sink,
                "unsanitized flows": "yes", # TODO
                "sanitized flows": [] # TODO
            }

            vulns += [vuln]

    return vulns

def main(tree, patterns):
    """Main program"""

    root = Node("", {}).make_child(tree)
    output = []
    # root.print_tree()
    # root.taint_nodes()

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

        # Check if there are any tainted sinks and append them to vuln list
        output += check_any_tainted_sinks(variables, pattern)

    # Write output to file
    with open("ola.json", "w") as output_file:
        output_file.write(json.dumps(output))

    # Print output
    pprint(output)

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
