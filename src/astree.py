import itertools
import pprint
import re

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

l1 = [ASSIGN, EXPR, IF, WHILE]
l2 = [BINOP, CALL, COMPARE, ATTRIBUTE]
l3 = [NAME, CONSTANT]

# All flows
global program_flows
program_flows = []

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

# Static list of sanitizing functions. You would think sans.keys() would always equal this. Yes..
global sanitizers
sanitizers = []

# Static list of sources
global sources
sources = []

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
        sinks = {key: [] for key in pattern['sinks']}

        # Remove sinks from dictionary TODO
        # [variables.pop(key) for key, _ in sinks.items()]

        return sinks

    def extract_sans(self, pattern):
        """Returns a dictionary with sans names as keys and an empty list as value.
        This is meant to be called after extract_variables."""
        global variables, sans, sanitizers, sources

        # Add sans to their own struct
        sans = {key: [] for key in pattern['sanitizers']}
        sanitizers = pattern['sanitizers'].copy()
        sources = pattern['sources'].copy()

        # Remove sans from dictionary TODO
        # [variables.pop(key) for key, _ in sans.items()]

        return sans

    def init_variables(self):
        """Returns a dictionary with all variables in the program marked as uninitialized.
        """
        global variables, inits

        inits = {var: False for var, value in variables.items()}

        return inits

    def execute(self):
        global program_flows
        counter=1
        for key, value in self.children.items():
            for child in value:
                #for line of code
                print('LINE '+str(counter))
                child.taint_nodes()
                counter+=1
                print('semi final')
                print(program_flows[len(program_flows)-1])
                self.merge_flows()
                self.dup_flows()
        print('b4 clean')
        for p in program_flows:
            print(p)
        program_flows=[p for p in program_flows if p.source and p.sink]

    def dup_flows(self):
        global program_flows, sources
        bad=[p for p in program_flows if p.source and p.sink]
        for b in bad:
            all_sources=[el for el in b.chain if el in sources]
            if len(all_sources)>1:
                for source in all_sources:
                    if source!=b.source:
                        f=Flow()
                        f.source=



    def merge_flows(self):
        global program_flows
        new_flows = []
        latest=program_flows.pop()
        if len(latest.children)>0:
            print('MERGING')
            latest.merge(new_flows)
            print('NEW')
            for y in new_flows:
                if y:
                    print(y.chain)
                    program_flows.append(y)
        else:
            program_flows.append(latest)


    def taint_nodes(self, flow=Flow()):
        """Taint every node that has been 'in contact' with a source.
        Build taint chains."""

        global variables, sinks, sans, san_flows, sanitizers, program_flows, sources

        if self.ast_type in l1:

            if self.ast_type == ASSIGN:

                # Declare target as initialized
                # WARNING, NOT GUARANTEED THAT TARGETS IS L3!
                for child in self.children["targets"]:
                    inits[child.attributes["id"]] = True

                # Right hand side of assignment
                val = self.children["value"][0]
                node_type = val.attributes["ast_type"]

                # One flow per assign
                #WARNING, estou a assumir q so ha 1 flow, mas se forem varios targets i guess q ha mais
                f=Flow()
                
                val.taint_nodes(f)


                for child in self.children["targets"]:
                    var=child.attributes["id"]
                    f.chain.append(var)
                    if var in sinks:
                        f.sink=var
                program_flows.append(f)
                
                #TODO
                # # Tainting flows is a recursive list of flows from a source
                # tainting_flows = val.is_tainted(f)


                # if tainting_flows:
                #     # If there are any, the left part is now tainted by all the variables in the flows
                #     tainters = self.get_tainters(tainting_flows)
                    
                #     # If value is tainted, taint the left-hand side (targets)
                #     for child in self.children["targets"]:

                #         # Tainting the targets with all the children of value
                #         # NOT GUARANTEED THAT TARGETS IS L3!
                #         for t in tainters:
                #             variables[child.attributes["id"]].extend(variables[t] + [t])
                #             sink = child.attributes["id"]

                #             if sink in sinks.keys():
                #                 # We need to get any sanitizing functions for each of the flows therein
                #                 child.get_full_flow() # Should return all contamination chain + sanitizers
                                
                #                 # Whenever a sink gets tainted, we need to check if the tainters have been sanitized
                #                 sinks[sink] = variables[sink]
                                
                #                 if t not in san_flows.keys():
                #                     san_flows[t] = []

                #                 if t in sans.keys():
                #                     san_flows[t] += [sans[t]]
                #                     san_flows[t] = list(set(san_flows[t]))

                #                 #flows[sink] = Flow(source, tainters, sanitizers)


                #         # Clean up possible duplicates
                #         variables[child.attributes["id"]] = list(set(variables[child.attributes["id"]]))


            elif self.ast_type == EXPR:
                # expr is always a value..
                exp = self.children["value"][0]

                f=Flow()

                exp.taint_nodes(f)

                program_flows.append(f)

            elif self.ast_type == IF:
                pass

            elif self.ast_type == WHILE:
                pass

        elif self.ast_type in l2:

            if self.ast_type == CALL:

                function_name = self.attributes["func"]["id"]
                
                # Removing functions from initializations
                inits.pop(function_name, None)

                #TODO if fucntion is sanitizer

                for arg in self.children["args"]:
                    f=Flow()
                    flow.children.append(f)
                    arg.taint_nodes(f)
                    f.chain.append(function_name)

                if len(self.children["args"])==0:
                    flow.chain.append(function_name)

                if function_name in sources:
                    flow.source=function_name

                if function_name in sinks:
                    flow.sink=function_name

                #TODO ?????????
                # res=self.check_flow_sources(function_name)

                # if res:
                #     flow.chain.extend(res.chain)
                #     flow.source=res.source
                # else:
                #     flow.chain.append(function_name)
                #     # If I am source
                #     if function_name in sources:
                #         flow.source=function_name

                    
                

            elif self.ast_type == BINOP:
                left=self.children["left"][0]
                right=self.children["right"][0]
                left.taint_nodes(flow)
                right.taint_nodes(flow)

            elif self.ast_type == ATTRIBUTE:
                pass
            elif self.ast_type == COMPARE:
                pass
        elif self.ast_type in l3:
            if self.ast_type == NAME:
                # Check my own id and query variables dict
                node_id = self.attributes["id"]
                if (node_id in inits and not inits[node_id] and node_id not in sources):
                    sources.append(node_id)

                res=self.check_flow_sources(node_id)

                if res:
                    for fl in res:
                        flow.chain.extend(fl.chain)
                        flow.source=fl.source
                    flow.chain=list(set(flow.chain))
                else:
                    flow.chain.append(node_id)
                    # If I am source
                    if (node_id in sources):
                        flow.source=node_id
            

            elif self.ast_type == CONSTANT:
                flow.chain.append('CONSTANT')

        

    def check_flow_sources(self,var):
        global program_flows
        ret=[]
        for f in program_flows:
            if var in f.chain and f.source:
                ret.append(f)
        return ret




    def taint_children(self, tainter):
        """Taints children of node"""
        for key, value in self.children.items():
            for child in value:
                if "id" in child.attributes.keys():
                    variables[child.attributes["id"]] += tainter
                    variables[child.attributes["id"]] = list(
                        set(variables[child.attributes["id"]]))

                child.taint_children(tainter)

    def sanitizes(self):
        """Returns sanitizers of this node"""

        global variables, inits

        # Check my own id and query variables dict
        node_id = self.attributes["id"] if "id" in self.attributes else None

        # If I am source
        if (node_id in sources) or (node_id in inits and not inits[node_id]):
            return [node_id]

        # If my ID is in the variables dict (which should be unless None) and it has a non-empty list, I'm tainted
        if node_id in variables and variables[node_id]:
            return list(set(variables[node_id] + [node_id]))

        # Get all children bundled into one single array
        children_array = [child.is_tainted()
                          for key, value in self.children.items() for child in value]

        # Removing dead entries
        clean = [c for c in children_array if c]
        if len(clean) == 1:
            clean = clean[0]

        # If one of my children is tainted, I am tainted + !! all my other children until the same level are tainted !! IMPORTANT: tell joao
        return clean

    def get_tainters(self, flows):
        """Recursive function to merge a recursive list  (a list of lists of lists of..."""

        clean = []
        for flow in flows: 
            if isinstance(flow, list): 
                flow = self.get_tainters(flow) #separate multiple-line outputs with newlines
                clean += flow
            else:
                clean += [flow]

        return clean

    def get_variables(self):
        """Return the global dictionary of variables"""
        global variables, sinks, sans, san_flows, inits
        return variables, sinks, sans, san_flows, inits

    def reset_variables(self):
        """Resets variables from other traversals"""
        global variables, sinks, sans, san_flows, inits, sanitizers, sources, program_flows
        variables = {}
        sinks = {}
        sans = {}
        san_flows = {}
        inits = {}
        sanitizers = []
        sources = []
        program_flows = []

    def get_flows_and_sources(self):
        global program_flows, sources
        return program_flows, sources