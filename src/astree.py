import pprint

DISCARD = ["lineno", "end_lineno", "col_offset", "end_col_offset"]
EXPR = "Expr"
ASSIGN = "Assign"
IF = "If"
WHILE = "While"

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

    def __init__(self, ast_type: str, children: list) -> None:
        self.ast_type = ast_type
        self.children = children
        self.cool_children = {}

    def make_child(self, child: dict):
        """Entry point function to create the tree.

        Iterate over every attribute.
        If one of them is a dict, this child has a child.
        If one of them is a list, we need to make_children on that list.

        Returns a single child.
        """

        self.clean_child(child)

        new_node = Node(child["ast_type"], [child])

        for key, value in child.items():
            if isinstance(value, dict):
                new_child = [self.make_child(value)]
                new_node.add_child(new_child)
                new_node.cool_children[key] = new_child

            elif isinstance(value, list):
                new_node.add_child(self.make_children(value))
                new_node.cool_children[key] = self.make_children(value)

        return new_node

    def make_children(self, children: list):
        """Returns a list of Nodes that correspond to the children."""

        return [self.make_child(child) for child in children]

    def add_child(self, child: list) -> None:
        """Add an iterable amount of children to this node's current children pool."""

        self.children += child

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

        print(self.ast_type, len(self.children))

        for child in self.children:
            if isinstance(child, Node):
                child.print_tree()
            else:
                pprint.pprint(child)
                print()

    def get_variables(self, pattern):
        """Returns a dictionary with variable names as keys and 'taint chain' as value.
        We consider a 'taint chain' to be the sequence of variables that as led to the key
        being tainted."""

        global variables

        # Traverse tree and extract every "id"
        # TODO: Is it safe to assume the ID will always be in the first child
        if "id" in self.children[0] and self.children[0]["id"] not in variables:
            variables[self.children[0]["id"]] = []

        for child in self.children:
            if isinstance(child, Node):
                child.get_variables(pattern)

        for source in pattern['sources']:
            variables[source] = [source]

        return variables

    def taint_nodes(self):
        """Taint every node that has been 'in contact' with a source.
        Build taint chains."""

        global variables
        
        if self.ast_type == ASSIGN:
            # If the right part of this assignment is tainted, the left one is now tainted
            for child in self.children:
                if isinstance(child, dict):
                    print(child["value"])
                    if child["value"].is_tainted():
                        print("ERRO ERRO ERRO", child)


        elif self.ast_type == EXPR:
            pass

        elif self.ast_type == IF:
            pass

        elif self.ast_type == WHILE:
            pass

        for child in self.children:
            if isinstance(child, Node):
                child.taint_nodes()

    def is_tainted(self):
        """Returns whether this node has been tainted by one of its children"""

        global variables

        # Check my own id and query variables dict
        node_id = self.children[0]["id"] if "id" in self.children[0] else None

        # If my ID is in the variables dict (which should be unless None) and it has a non-empty list, I'm tainted
        if node_id in variables and variables[node_id]:
            return True

        for child in self.children:
            if isinstance(child, Node):
                if child.is_tainted():
                    return True

        return False
