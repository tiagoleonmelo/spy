import ast
from logger import Logger

log = Logger.get_logger("spy")

class ConstantLister(ast.NodeVisitor):
    def visit_Constant(self, node: ast.Constant):
        log.info(node.value)
        return super().visit_Constant(node)