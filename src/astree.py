import itertools
import pprint

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

l1 = [ASSIGN, EXPR, IF, WHILE]
l2 = [BINOP, CALL, COMPARE, ATTRIBUTE]
l3 = [NAME, CONSTANT]

# Keep tab of what variables tainted each other
global variables
variables = {}

# Keep tab of tainted sinks
global sinks
sinks = {}

# Keep tab of which variables have been sanitized
global sans # In days like these, kids like you..
sans = {}

# Keep tab of the sanitization flows that have occurred whenever a sink is reached
global san_flows
san_flows = {}

# Keep tab of what variables have been initialized
global inits
inits = {}

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

    def __init__(self, ast_type: str, attributes: dict) -> None:
        self.ast_type = ast_type
        self.children = {}
        self.attributes = attributes

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
            variables[source] = [source]

        return variables

    def extract_sinks(self, pattern):
        """Returns a dictionary with sink names as keys and an empty list as value.
        This is meant to be called after extract_variables."""
        global variables, sinks

        # Add sinks to their own struct
        sinks = {key: [] for key, _ in variables.items() if key in pattern['sinks']}

        # Remove sinks from dictionary TODO
        # [variables.pop(key) for key, _ in sinks.items()]

        return sinks

    def extract_sans(self, pattern):
        """Returns a dictionary with sans names as keys and an empty list as value.
        This is meant to be called after extract_variables."""
        global variables, sans

        # Add sans to their own struct
        sans = {key: [] for key, _ in variables.items() if key in pattern['sanitizers']}

        # Remove sans from dictionary TODO
        # [variables.pop(key) for key, _ in sans.items()]

        return sans

    def init_variables(self):
        """Returns a dictionary with all variables in the program marked as uninitialized.
        """
        global variables, inits

        inits = {var: False for var, value in variables.items()}

        return inits

    def taint_nodes(self):
        """Taint every node that has been 'in contact' with a source.
        Build taint chains."""

        global variables, sinks, sans, san_flows

        if self.ast_type in l1:

            if self.ast_type == ASSIGN:

                # Declare target as initialized
                for child in self.children["targets"]:
                    inits[child.attributes["id"]] = True

                # Right hand side of assignment
                val = self.children["value"][0]
                node_type = val.attributes["ast_type"]
                
                if node_type in l2:
                    val.taint_nodes()

                tainter = val.is_tainted()

                if tainter:
                    # If value is tainted, taint the left-hand side (targets)
                    for child in self.children["targets"]:
                        #print(child.attributes["id"]+' contaminated by '+tainter[0])

                        # Tainting the targets with all the children of value
                        # NOT GUARANTEED THAT TARGETS IS L3!
                        for t in tainter:
                            variables[child.attributes["id"]].extend(variables[t] + [t])

                        # Clean up possible duplicates
                        variables[child.attributes["id"]] = list(set(variables[child.attributes["id"]]))

                        if child.attributes["id"] in sinks.keys(): # This is only needed because sometimes sinks arent functions
                            # Whenever a sink occurs, we need to check if the tainters have been sanitized
                            sinks[child.attributes["id"]] = variables[child.attributes["id"]]
                            
                            if t not in san_flows.keys():
                                san_flows[t] = []
                            
                            if t in sans.keys():
                                san_flows[t] += sans[t]
                                san_flows[t] = list(set(san_flows[t]))

            elif self.ast_type == EXPR:

                # expr is always a value..
                exp = self.children["value"][0]

                exp.taint_nodes()

            elif self.ast_type == IF:
                pass

            elif self.ast_type == WHILE:
                pass

        elif self.ast_type in l2:

            if self.ast_type == CALL:
                # NOT GUARANTEED THAT FUNC IS L3!
                # If one arg is tainted taint the others, and taint victim -> I dont think we should taint the victim.
                # A function can be tainted but I dont think it should be able to taint other elements:
                #
                #   a = f(b, c) // where b is a source
                #   r = f(w, q) // where there are no sources
                #
                # If we consider f gets tainted in the first line r, w and q will be tainted in the second one.
                # OTOH if f does not get tainted, how will we spot tainted sinks?
                #
                # I want functions to get tainted, but I dont want them to taint other things.
                #
                # Idea: what if we NEVER taint functions, but we have an additional data structure keeping tabs
                # of the sinks that have been tainted?
                #
                # I think this is good. Depois no fim não fazemos nenhum pass pelo global variables, mas sim
                # por esta struct que só tem os sinks q foram tainted e por quem
                # We have a structure to keep record of the tainting, and a structure to keep record of the sinks.
                #
                # Its hard though.
                # Yolo, committing before breaking changes.
                #
                # So, to taint we only read from `variables`, and at the end we only read from `sinks`
                function_name = self.attributes["func"]["id"]
                
                # Removing functions from initializations
                inits.pop(function_name, None)

                # We need to know if this is a sink or a san function
                if function_name in sinks.keys():
                    # Taint arguments mutually and then taint the sink with its arguments
                    for arg in self.children["args"]:
                        tainters = arg.is_tainted()
                        for t in tainters:
                            # Whenever a sink is tainted, we need to check if the tainters have been sanitized
                            sinks[function_name].extend(variables[t] + [t])
                            sinks[function_name] = list(set(sinks[function_name]))

                            if t not in san_flows.keys():
                                san_flows[t] = []

                            if t in sans.keys():
                                san_flows[t] += sans[t]
                                san_flows[t] = list(set(san_flows[t]))
                                                
                elif function_name in sans.keys():
                    # We need to include that this function sanitized a flow.
                    # What should this struct look like?..
                    # {san_func: san_var}? and in the end we check if any of the variables that tainted
                    # a given sink has an entry in this dict?... might be...
                    for arg in self.children["args"]:
                        tainters = arg.is_tainted()
                        for t in tainters:
                            if t not in sans.keys():
                                sans[t] = []

                            sans[t] += [function_name]
                            sans[t] = list(set(sans[t]))

                            sans[function_name] += [t]
                            sans[function_name] = list(set(sans[function_name]))

                else: # If the function is neither a sink nor a san
                    pass

            elif self.ast_type == BINOP:
                # ...
                pass

            elif self.ast_type == ATTRIBUTE:
                pass
            elif self.ast_type == COMPARE:
                pass
        elif self.ast_type in l3:
            if self.ast_type == NAME:
                pass
            elif self.ast_type == CONSTANT:
                pass

        # right?
        for key, value in self.children.items():
            [child.taint_nodes() for child in value]

    def taint_children(self, tainter):
        """Taints children of node"""
        for key, value in self.children.items():
            for child in value:
                if "id" in child.attributes.keys():
                    variables[child.attributes["id"]] += tainter
                    variables[child.attributes["id"]] = list(
                        set(variables[child.attributes["id"]]))

                child.taint_children(tainter)

    def is_tainted(self):
        """Returns whether this node has been tainted by one of its children, and who"""

        global variables, inits

        # Check my own id and query variables dict
        node_id = self.attributes["id"] if "id" in self.attributes else None

        # If I have not been initialized, I am source
        if node_id in inits and not inits[node_id]:
            return [node_id]

        # If my ID is in the variables dict (which should be unless None) and it has a non-empty list, I'm tainted
        if node_id in variables and variables[node_id]:
            return variables[node_id] + [node_id]

        # Get all children bundled into one single array
        children_array = [child.is_tainted()
                          for key, value in self.children.items() for child in value]

        # Merge all arrays into a single array (from https://stackoverflow.com/a/716482)
        # This will be problematic once multiple children have been tainted by the same source! => Duplicate entries
        # Since order does not really matter, maybe we can just `set` it
        merged = list(set(itertools.chain.from_iterable(children_array)))

        # If one of my children is tainted, I am tainted + !! all my other children until the same level are tainted !! IMPORTANT: tell joao
        return merged

    def get_variables(self):
        """Return the global dictionary of variables"""
        global variables, sinks, sans, san_flows, inits
        return variables, sinks, sans, san_flows, inits

    def reset_variables(self):
        """Resets variables from other traversals"""
        global variables, sinks, sans, san_flows, inits
        variables = {}
        sinks = {}
        sans = {}
        san_flows = {}
        inits = {}