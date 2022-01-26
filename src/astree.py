import itertools
import pprint

from flow import Flow

# Attributes to discard from the given AST
DISCARD = ["lineno", "end_lineno", "col_offset", "end_col_offset"]

# Level 1
EXPR = "Expr"
ASSIGN = "Assign"
IF = "If"
WHILE = "While"

# Level 2
BINOP = "BinOp"
CALL = "Call"
COMPARE = "Compare"
ATTRIBUTE = "Attribute"

# Level 3
NAME = "Name"
CONSTANT = "Constant"

# Keep tab of what variables tainted each other
global variables
variables = {}

# Variable that will be used to build the output
global san_flows
san_flows = {}

# Keep tab of what variables have been initialized
global inits
inits = {}

# Static list of sanitizing functions
global sanitizers
sanitizers = []

# Static list of sources
global sources
sources = []

# Static list of sinks
global sinks
sinks = []

"""
Rules of thumb
* A variable is only tainted upon assignment
* A function is thus never tainted
"""


class Node:
    """Tree Node. Contains the ast_type and all its attributes and children are stored in children.

    A visual representation of helloworld.json would look like this:

    Module--------------------
    attr:body (array of nodes)
    |
    Expr------
    attr:value
    |
    Call-------------------------------------
    attr:args                       attr:func
    |                               |
    Constant------------------      Name----
    attr:value = "Hello World"      attr:ctx
                                    |
                                    Load----

    We have a Module root node which contains an array of nodes. In this case, only one - an Expr node. One of the attributes of an Expr node is value,
    which stores another node, this time of type Call. Call has an attribute args, which contains an array of nodes (in this case, also only one) - Constant.
    Constant has an attribute called value which holds "Hello World".

    - Should we discard ast_type-specific naming for the children? Instead of body/value/argues should it just be a Node attribute called "children"? Or
    is it relevant for the problem? -> No, we should not. A Call node (for example) has children in attr:args and attr:func. We can't merge.
    - We must handle these main node types, and its nestings:
        * Expr
        * Assign
        * If
        * While

    Anything other than these is extra (as per project presentation)
    """

    # # Building the tree
    # # # # # # # # # # # # # # #
    
    def __init__(self, ast_type: str, attributes: dict) -> None:
        self.ast_type = ast_type
        self.attributes = attributes
        self.children = {}

    def make_child(self, child: dict):
        """Entry point function to create the tree.

        Iterate over every attribute.
        If one of them is a dict, this child has a child.
        If one of them is a list, we need to make_children on that list.

        Returns a single child.
        """

        self.clean_child(child)

        new_node = Node(child["ast_type"], child)

        for key, value in child.items():
            if isinstance(value, dict):
                new_child = [self.make_child(value)]
                new_node.children[key] = new_child

            elif isinstance(value, list):
                new_node.children[key] = self.make_children(value)

        return new_node

    def make_children(self, children: list):
        """Returns a list of Nodes that correspond to the children."""

        return [self.make_child(child) for child in children]

    def clean_child(self, child: dict):
        """Remove irrelevant/redundant attributes from the child and its children."""

        for attr in DISCARD:
            child.pop(attr, None)

        for _, value in child.items():
            if isinstance(value, dict):
                self.clean_child(value)
            elif isinstance(value, list):
                [self.clean_child(c) for c in value]

    def print_tree(self):
        """Print the tree."""

        print('+', end=' ')
        print(self.ast_type, sum([len(value)
                                  for _, value in self.children.items()]))
        pprint.pprint(self.attributes)

        for key, child in self.children.items():
            print(key)
            [c.print_tree() for c in child]

    # # Analyzing the tree
    # # # # # # # # # # # # # # #

    def extract_variables(self, pattern):
        """Returns a dictionary with variable names as keys and 'taint chain' as value.
        We consider a 'taint chain' to be the sequence of variables that has led to the key
        being tainted."""

        global variables

        # Traverse tree and extract every "id"
        if "id" in self.attributes and self.attributes["id"] not in variables:
            variables[self.attributes["id"]] = []

        for key, value in self.children.items():
            [child.extract_variables(pattern) for child in value]

        for source in pattern['sources']:
            variables[source] = [Flow(source, [])]

        return variables

    def extract_static(self, pattern):
        """Initialize all static variables"""
        global variables, sanitizers, sources, sinks, inits

        sanitizers = pattern['sanitizers'].copy()
        sources = pattern['sources'].copy()
        sinks = pattern['sinks'].copy()
        inits = {var: False for var, value in variables.items()
                 if var not in sanitizers}

    def taint_nodes(self):
        """Main function that will iterate through a program"""

        # We will only be tainting variables in this branch
        if self.ast_type == ASSIGN:
            # Declare target as initialized
            for child in self.children["targets"]:
                inits[child.attributes["id"]] = True

            # Right hand side of assignment
            value = self.children["value"][0]
            if value.is_tainted():
                # If there are any, the targets will inherit sources and sanitizers
                for child in self.children["targets"]:
                    child_name = child.attributes["id"]

                    flows = value.get_flows()  # Should return list of flows (source + sanitizers) inside val
                    variables[child_name] += flows

                    # If the target is a sink, write to output
                    if child_name in sinks:
                        san_flows[child_name] = flows

        elif self.ast_type == EXPR:
            # Expr is always a value
            exp = self.children["value"][0]
            exp.get_flows()

        elif self.ast_type == IF:
            # Recursive call for every node in body
            pass

        elif self.ast_type == WHILE:
            pass

        #print(self.ast_type, self.children)

        # Recursive call to children
        for key, value in self.children.items():
            [child.taint_nodes() for child in value]

    def is_tainted(self):
        """Returns flows that tainted this node"""

        global variables, inits

        # Check my own id and query variables dict
        node_id = self.attributes["id"] if "id" in self.attributes else None

        # If I am source
        if (node_id in sources) or (node_id in inits and not inits[node_id]):
            return Flow(node_id, [])

        # If my ID is in the variables dict (which should be unless None) and it has a non-empty list, I'm tainted
        if node_id in variables and variables[node_id]:
            return variables[node_id]

        # Get all children bundled into one single array
        children_array = [child.is_tainted()
                          for key, value in self.children.items() for child in value]

        # Removing dead entries
        clean = [c for c in children_array if c]

        # If one of my children is tainted, I am tainted + !! all my other children until the same level are tainted !! IMPORTANT: tell joao
        return clean

    def get_flows(self):
        """Called when sorting out Level 2 operations.
        Returns a list of flows (source + sanitizers)"""

        if self.ast_type == CALL:
            # In a call, we can either have a sink or a sanitizer
            # If this is a source, the assignment branch will already cover it
            function_name = self.attributes["func"]["id"]

            # Functions dont have to be initialized
            inits.pop(function_name, None)

            arg_flows = []

            # Get arguments
            for arg in self.children['args']:
                # Recursive call
                arg_flows += arg.get_flows()

            # If this is a sink
            if function_name in sinks:
                # Add to output list
                # TODO: Append?
                san_flows[function_name] = arg_flows

                # Return recursive call
                return arg_flows

            # If this is a sanitizer
            elif function_name in sanitizers:
                # Every flow within these arguments has now been sanitized by function_name
                # Creating a copy of the flows in order not to modify global variables
                cpy = [Flow(arg_flow.source, arg_flow.sanitizers.copy())
                       for arg_flow in arg_flows]

                [arg_flow.sanitizers.append(function_name) for arg_flow in cpy]

                # Return a list (source, [sanitizers + function_name]) for each arg_flow
                return cpy

            # If this is a source
            elif function_name in sources:
                # Return a list (flow) for flow in x + (function_name, [])
                return arg_flows + [Flow(function_name, [])]

            # If the function is neither a sink, source, nor san
            return arg_flows

        elif self.ast_type == BINOP:
            binop_flows = []

            # Depth-first fetch of all operands
            for key, value in self.children.items():
                # Recursive call
                binop_flows += [child.get_flows() for child in value]

            merged = list(itertools.chain.from_iterable(binop_flows))

            # Should return a list of flows with all the sources and sanitizers
            return merged

        # If this is not a call, just return a flow if this is tainted
        var_name = self.attributes["id"] if "id" in self.attributes else None

        if var_name in inits and not inits[var_name]:
            return [Flow(var_name, [])]
        elif var_name in variables:
            return variables[var_name].copy()

        return []

    def split_program(self, instructions):
        # Given a set of nodess
        # For every if that we find
        # Return a program that considers condition true
        # Return a program that considers condition false
        # A program is a list of nodes
        programs = [[]]
        
        # Assumes I am either Module or If
        for child in instructions:

            # If this is an If, I will split all existing programs so that they consider its body and orelse
            # I will also make a recursive call here, since ifs can be nested
            if child.ast_type == IF:
                # Fetch the sets of nodes that can be executed
                if_body = child.split_program(child.children["body"])
                orelse = child.split_program(child.children["orelse"])

                parallel = []

                # Duplicating programs and making parallel universes
                # This might not do well with many nested ifs. Unsure.
                for prog in programs:
                    for if_possibility in if_body:
                        parallel_universe = prog.copy()
                        parallel_universe.extend(if_possibility)
                        parallel += [parallel_universe]

                    for else_possibility in orelse:
                        prog.extend(else_possibility)
                        parallel += [prog]

                programs = parallel.copy()

            # Everytime I encounter a non-branching child, I add it to every program
            else:
                for prog in programs:
                    prog += [child]

        return programs

    def merge_lists(self, flows):
        """Recursive function to merge a recursive list  (a list of lists of lists of..."""

        clean = []

        for flow in flows:
            if isinstance(flow, list):
                # separate multiple-line outputs with newlines
                flow = self.merge_lists(flow)
                clean += flow
            else:
                clean += [flow]

        return clean

    # # Getters and setters
    # # # # # # # # # # # # # # #

    def get_variables(self):
        """Return the global dictionary of variables"""
        global variables, san_flows, inits
        return variables, san_flows, inits

    def reset_variables(self):
        """Resets variables from other traversals"""
        global variables, san_flows, inits, sanitizers, sources, sinks
        variables = {}
        san_flows = {}
        inits = {}
        sanitizers = []
        sources = []
        sinks = []

    def __str__(self) -> str:
        if self.ast_type == ASSIGN:
            targets = ', '.join([c.attributes["id"] for c in self.children["targets"]])
            return self.ast_type + ' (' + targets + ')'
        return self.ast_type

    def __repr__(self) -> str:
        return str(self)
