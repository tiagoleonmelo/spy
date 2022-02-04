#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import json
import os
from pprint import pprint
from pathlib import Path

from astree import Node
from flow import Flow, MergedFlow
from logger import Logger

global counter
counter = 1

OUTPUT_DIR = '../tests/'
log = Logger.get_logger("spy")


def check_any_tainted_sinks(san_flows, pat):
    """Given the final state of a tree traversal and a pattern, checks which sinks have been tainted.
    Returns a list of dictionaries for every vulnerability found"""

    global counter
    vulns = []

    for sink in pat["sinks"]:
        if sink in san_flows and san_flows[sink]:
            # For each tainted sink create as many vulns as there are flows tainting it!
            flows = san_flows[sink]
            #log.debug("Sink %s tainted by %s" %
                      #(sink, ', '.join([f.source for f in flows])))

            # Merge all flows with same source in this sink
            merged_flows = []
            found_srcs = sorted(list(set([fl.source for fl in flows])))

            for src in found_srcs:
                tmp = [flow for flow in flows if flow.source == src]
                merged_flow = MergedFlow(src, [f.sanitizers for f in tmp])
                merged_flows += [merged_flow]

            for flow in merged_flows:
                # Check if all flows have been sanitized:
                #  if there is an empty sanitization, there is an unsan flow
                has_unsan_flows = "yes" if [] in flow.sanitizers else "no"

                # Clear any unsan flows
                clean_sans = [san for san in flow.sanitizers if san]

                vuln = {
                    "vulnerability": pat["vulnerability"] + '_' + str(counter),
                    "source": flow.source,
                    "sink": sink,
                    "unsanitized flows": has_unsan_flows,
                    "sanitized flows": clean_sans
                }

                counter += 1
                vulns += [vuln]

    return vulns

def final_merge(output, patterns):
    """Merge flows given a list of vulnerability dictionaries"""
    found_srcs = sorted(list(set([vuln["source"] for vuln in output])))
    found_sinks = sorted(list(set([vuln["sink"] for vuln in output])))
    vulns = []

    for pat in patterns:
        final_counter = 1
        for sink in found_sinks:
            for src in found_srcs:
                tmp = [vuln for vuln in output if vuln["source"] == src and vuln["sink"]
                       == sink and vuln["vulnerability"].split('_')[0] == pat["vulnerability"]]

                if not tmp:
                    continue

                first = sorted(tmp, key=lambda x: x["vulnerability"])[0]
                merged_flow = []
                for f in tmp:
                    merged_flow.extend(f["sanitized flows"])

                # If one of the vulns being merged has an unsan flow, the new vuln will have unsan flows
                has_unsan_flows = "yes" if "yes" in [t["unsanitized flows"] for t in tmp] else "no"

                # Clear any unsan flows
                clean_sans = [list(set(san)) for san in merged_flow if san]

                # Remove duplicate sanizitation flows
                clean_sans = remove_duplicates(clean_sans)

                new_vuln = {
                    "vulnerability": first["vulnerability"].split('_')[0] + '_' + str(final_counter),
                    "source": src,
                    "sink": sink,
                    "unsanitized flows": has_unsan_flows,
                    "sanitized flows": clean_sans
                }

                vulns += [new_vuln]
                final_counter += 1

    return sorted(vulns, key= lambda x: x["vulnerability"])

def remove_duplicates(l):
    """Remove duplicate lists in a list of lists"""
    new_list = []
    for elem in l:
        if elem not in new_list:
            new_list.append(elem)

    return new_list

def main(tree, patterns, program_name):
    """Main program"""

    global counter
    root = Node("", {}).make_child(tree)
    output = []

    for pattern in patterns:
        log.debug("+ Analysing program %s - pattern %s" % (program_name, pattern["vulnerability"]))

        # Clean previous variables and counters
        root.reset_variables()
        counter = 1

        # Split the program into all its possible execution flows
        subtrees = root.split_program(root.children["body"])

        # Analyse every possible execution flow
        for sub in subtrees:
            #log.debug("++ Analyzing execution flow " + str(sub))

            # Create fake root node
            subroot = Node("Module", {})
            subroot.children["body"] = sub
            subroot.reset_variables()

            # Get program variables and taint the sources
            root.extract_variables(pattern)
            root.extract_static(pattern)
            #log.debug("Successfully extracted variables and sinks from program")

            # Fetch variables program - global state of the program
            variables, san_flows, inits = root.get_variables()
            #log.debug(variables)

            subroot.taint_nodes()

            output += check_any_tainted_sinks(san_flows, pattern)

        # We now check if there are any implicit flows in the full tree
        if pattern["implicit"] == "yes":
            #log.debug("++ Checking for implicit flows in root")
            root.reset_variables()

            root.extract_variables(pattern)
            root.extract_static(pattern)
            #log.debug("Successfully extracted variables and sinks from program")
            
            # Fetch variables program - global state of the program
            variables, san_flows, inits = root.get_variables()
            
            # Check every conditional body
            # If in the condition there is a source or tainted variables
            root.check_implicit()

            output += check_any_tainted_sinks(san_flows, pattern)

    # Merge vulns with same source / sink
    output = final_merge(output, patterns)

    # Write output to file
    with open(os.path.join(OUTPUT_DIR, program_name, program_name + ".output.json"), "w") as output_file:
        output_file.write(json.dumps(output, indent=4))

    return 0


if __name__ == "__main__":

    if len(sys.argv) != 3:
        log.error(
            "Please provide an AST of the program slice to parse and vulnerability patterns."
        )
        log.error(
            "Usage:\n\tpython main.py <input_slice.json> <vulnerability_patterns.json>\n\t" \
            "or\n\t" \
            "python main.py -t <number_of_tests>\n"
        )
        sys.exit(1)

    if "-t" == sys.argv[1]:
        perfect = True

        try:
            n_programs = int(sys.argv[2])
            assert n_programs > 0
            assert n_programs < 16
        except:
            log.error("Please provide a valid number of tests (1-15)")
            sys.exit(1)

        for subdir, dirs, files in os.walk('../tests'):
            for dir in dirs:
                if 'T43' in dir:
                    continue
                with open(os.path.join(subdir, dir, "input.json")) as slice_input:
                    tree = json.load(slice_input)

                try:
                    with open(os.path.join(subdir, dir, "patterns.json")) as pattern_input:
                        patterns = json.load(pattern_input)
                except:
                    with open(os.path.join(subdir, dir, "pattern.json")) as pattern_input:
                        patterns = json.load(pattern_input)

                main(tree, patterns, dir)

                out = os.path.join(subdir, dir, dir + ".output.json")
                out_reference = os.path.join(subdir, dir, "output.json")

                with open(out, "r") as f1:
                    out_file = sorted(json.loads(f1.read()),
                                    key=lambda x: x["vulnerability"])

                with open(out_reference, "r") as f2:
                    out_reference_file = sorted(json.loads(
                        f2.read()), key=lambda x: x["vulnerability"])

                if not (out_file == out_reference_file):
                    log.warn("Files not identical! Check %s\n" % dir)
                    perfect = False
                else:
                    log.info("Files %s identical\n" % dir)

        if perfect:
            log.info("All files identical ✅")

        log.info("Done")

        exit(0)

    with open(sys.argv[1]) as slice_input:
        tree = json.load(slice_input)
    #log.debug("Finished parsing tree")

    program_name = Path(sys.argv[1]).stem

    with open(sys.argv[2]) as pattern_input:
        patterns = json.load(pattern_input)
    #log.debug("Finished loading %d vulnerability patterns" % len(patterns))

    main(tree, patterns, program_name)

    log.info("Done")
