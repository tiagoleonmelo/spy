#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import ast
import json

from logger import Logger
from visitor import ConstantLister

log = Logger.get_logger("spy")


def main(tree, patterns):
    """Main program"""
    lister = ConstantLister()
    lister.visit(tree)
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
        tree = ast.parse(slice_input.read()) # Needs to be swapped out by a JSON AST parser, can't find any
    log.debug("Finished parsing tree")

    with open(sys.argv[2]) as pattern_input:
        patterns = json.load(pattern_input)
    log.debug("Finished loading %d vulnerability patterns" % len(patterns))

    main(tree, patterns)