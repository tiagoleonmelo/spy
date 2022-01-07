import pprint


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
    is it relevant for the problem?
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

    def add_child(self, child) -> None:
        """Add an iterable amount of children to this node's current children pool."""

        self.children += child

    def parse_dict(self, dictionary: dict):
        """Iterative function to build AST from slice of a program as a dictionary.
        Entry point."""

        root = Node(
            dictionary["ast_type"], self.make_children(dictionary["body"])
        )  # Always assumes the ast_type is "Module"

        return root

    def make_children(self, children: list):
        """Returns a list of Nodes that correspond to the children."""

        return [self.make_child(child) for child in children]

    def make_child(self, child: dict):
        """Iterate over every attribute.
        If one of them is a dict, this child has a child.
        If one of them is a list, we need to make_children on that list.

        Returns a single child.
        """

        # TODO: Create a method where we do this and discard irrelevant attributes (line/col numbers, ast_type, ...)
        new_node = Node(child["ast_type"], [child])

        for _, value in child.items():
            if isinstance(value, dict):
                new_child = [self.make_child(value)]
                new_node.add_child(new_child)
            elif isinstance(value, list):
                new_node.add_child(self.make_children(value))

        return new_node

    def print_tree(self):
        """Print the tree."""
        print(self.ast_type)
        for child in self.children:
            if isinstance(child, Node):
                child.print_tree()
            else:
                pprint.pprint(child)