#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import json
import os
from pprint import pprint
from pathlib import Path

from astree import Node
from logger import Logger

OUTPUT_DIR = 'output/'
log = Logger.get_logger("spy")


def check_any_tainted_sinks(vars, san_flows, inits, pat):
    """Given the final state of a tree traversal and a pattern, checks which sinks have been tainted.
    Returns a list of dictionaries for every vulnerability found"""

    vulns = []
    print(san_flows, vars)

    for sink in pat["sinks"]:
        if vars[sink]:
            # For each tainted sink create as many vulns as there are sources tainting it!
            tainting_sources = sorted(
                list(set([src for src in vars[sink] if src in pat["sources"] or (src in inits and not inits[src])])))
            log.debug("Sink %s tainted by %s" %
                      (sink, ', '.join(tainting_sources)))

            # We just need to fetch the sources from here, order does not matter
            for source in tainting_sources:

                flows = []
                tainted_flows = vars[sink].copy()

                print(pat["vulnerability"] + '_' + str(len(vulns) + 1), source, tainted_flows, san_flows, tainting_sources)

                for tainter in vars[sink]:
                    # If the tainter has a sanitization flow
                    if tainter in san_flows.keys():
                        tmp = [s for s in san_flows[tainter] if s]
                        # The flow is only valid if it matches the flow of the source (idk maybe)
                        print("tmp", tmp)
                        if tmp: # and (source in san_flows) and (san_flows[source] == tmp):
                            flows += tmp
                            tainted_flows.remove(tainter)

                print("flows", flows)
                # Check if all flows have been sanitized
                unsan_flows = "no" if len(tainted_flows) == 0 else "yes"

                vuln = {
                    "vulnerability": pat["vulnerability"] + '_' + str(len(vulns) + 1),
                    "source": source,
                    "sink": sink,
                    "unsanitized flows": unsan_flows,
                    "sanitized flows": flows
                }

                vulns += [vuln]

    return vulns


def main(tree, patterns, program_name):
    """Main program"""

    root = Node("", {}).make_child(tree)
    output = []
    # root.print_tree()
    # root.taint_nodes()

    for pattern in patterns:
        log.debug("Analysing pattern %s" % pattern["vulnerability"])
        # Clean previous variables
        root.reset_variables()

        # Get program variables and taint the sources
        root.extract_variables(pattern)
        root.extract_sinks(pattern)
        root.extract_sans(pattern)
        root.init_variables()
        log.debug("Successfully extracted variables and sinks from program")

        # Fetch variables program - global state of the program
        variables, sinks, sans, san_flows, inits = root.get_variables()
        log.debug(variables)
        log.debug(sinks)
        log.debug(sans)

        # Traverse tree and taint variables that have been in contact with sources
        root.taint_nodes()
        log.debug(variables)
        log.debug(sinks)
        log.debug(sans)

        # Check if there are any tainted sinks and append them to vuln list
        output += check_any_tainted_sinks(sinks, san_flows, inits, pattern)

    # Write output to file
    with open(os.path.join(OUTPUT_DIR, program_name + ".output.json"), "w") as output_file:
        output_file.write(json.dumps(output, indent=4))

    # Print output
    # pprint(output)

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

    if "-t" == sys.argv[1]:
        perfect = True

        try:
            n_programs = int(sys.argv[2])
            assert n_programs > 0
        except:
            log.error("Please provide a valid number of tests")

        program_list = ['1a-basic-flow.py', '1b-basic-flow.py',
                        '2-expr-binary-ops.py',
                        '3a-expr-func-calls.py', '3b-expr-func-calls.py',
                        '4a-conds-branching.py', '4b-conds-branching.py', ]

        for i in range(0, int(n_programs)):
            program = program_list[i]
            initial = program.split('-')[0]

            with open(os.path.join("slices", program + ".json")) as slice_input:
                tree = json.load(slice_input)

            with open(os.path.join("patterns", initial + "-patterns.json")) as pattern_input:
                patterns = json.load(pattern_input)

            main(tree, patterns, program)

            out = os.path.join("output", program + ".output.json")
            out_reference = os.path.join("output_ref", initial + "-output.json")

            with open(out, "r") as f1:
                out_file = sorted(json.loads(f1.read()), key=lambda x: x["vulnerability"])

            with open(out_reference, "r") as f2:
                out_reference_file = sorted(json.loads(f2.read()), key=lambda x: x["vulnerability"])

            if not (out_file == out_reference_file):
                log.warn("Files not identical! Check %s\n" % initial)
                perfect = False
            else:
                log.info("Files %s identical\n" % initial)

        if perfect:
            log.info("All files identical ✅")
        exit(0)

    with open(sys.argv[1]) as slice_input:
        tree = json.load(slice_input)
    log.debug("Finished parsing tree")

    program_name = Path(sys.argv[1]).stem

    with open(sys.argv[2]) as pattern_input:
        patterns = json.load(pattern_input)
    log.debug("Finished loading %d vulnerability patterns" % len(patterns))

    main(tree, patterns, program_name)
