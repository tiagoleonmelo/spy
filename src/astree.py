import itertools
import pprint

DISCARD = ["lineno", "end_lineno", "col_offset", "end_col_offset"]
#
EXPR = "Expr"
ASSIGN = "Assign"
IF = "If"
WHILE = "While"
#
BINOP= "BinOp"
CALL = "Call"
COMPARE = "Compare"
ATTRIBUTE = "Attribute"
#
NAME="Name"
CONSTANT="Constant"

l1=[ASSIGN,EXPR,IF,WHILE]
l2=[BINOP,CALL,COMPARE,ATTRIBUTE]
l3=[NAME,CONSTANT]

global variables
variables = {}

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
        print(self.ast_type, sum([len(value) for _, value in self.children.items()]))
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

    def taint_nodes(self):
        """Taint every node that has been 'in contact' with a source.
        Build taint chains."""

        global variables

        #print(variables)

        if self.ast_type in l1:

            if self.ast_type == ASSIGN:

                val = self.children["value"][0]

                node_type=val.attributes["ast_type"]
                if node_type in l2:
                    val.taint_nodes()

                tainter = val.is_tainted()

                if tainter:
                    # Taint the left-hand side
                    for child in self.children["targets"]:
                        #print(child.attributes["id"]+' contaminated by '+tainter[0])
                        #NOT GUARANTEED THAT TARGETS IS L3!
                        for x in tainter:
                            variables[child.attributes["id"]].extend(variables[x])
                        variables[child.attributes["id"]] += [y for y in tainter]

                        # Clean up spaghetti code
                        variables[child.attributes["id"]] = list(set(variables[child.attributes["id"]]))


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
                #NOT GUARANTEED THAT FUNC IS L3!
                victim = self.attributes["func"]["id"]
                #tainters->args, can be multiple
                for arg in self.children["args"]:
                    tainters=arg.is_tainted()
                    if tainters:
                        #if one arg is tainted taint the others, and taint victim
                        for x in tainters:
                            variables[victim].extend(variables[x])
                        variables[victim] += [y for y in tainters]
                        variables[victim] = list(set(variables[victim]))
            
            elif self.ast_type == BINOP:
                #...
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
        
        #right?
        for key, value in self.children.items():
            [child.taint_nodes() for child in value]

    def taint_children(self, tainter):
        """Taints children of node"""
        for key, value in self.children.items():
            for child in value:
                if "id" in child.attributes.keys():
                    variables[child.attributes["id"]] += tainter
                    variables[child.attributes["id"]] = list(set(variables[child.attributes["id"]]))

                child.taint_children(tainter)

    def is_tainted(self):
        """Returns whether this node has been tainted by one of its children, and who"""

        global variables

        #print(self.ast_type)

        # Check my own id and query variables dict
        node_id = self.attributes["id"] if "id" in self.attributes else None

        # If my ID is in the variables dict (which should be unless None) and it has a non-empty list, I'm tainted
        if node_id in variables and variables[node_id]:
            return variables[node_id] + [node_id]

        # Get all children bundled into one single array
        children_array = [child.is_tainted() for key, value in self.children.items() for child in value]

        # Merge all arrays into a single array (from https://stackoverflow.com/a/716482)
        # This will be problematic once multiple children have been tainted by the same source! => Duplicate entries
        # Since order does not really matter, we can just `set` it
        merged = list(set(itertools.chain.from_iterable(children_array)))
        
        # If one of my children is tainted, I am tainted + !! all my other children until the same level are tainted !! IMPORTANT: tell joao
        return merged

    def get_variables(self):
        """Return the global dictionary of variables"""
        global variables
        return variables

    def reset_variables(self):
        """Resets variables from other traversals"""
        global variables
        variables = {}

