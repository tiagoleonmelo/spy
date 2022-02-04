# assigning untainted values to tainted variables
# untaints them before they reach a sink
a = b
a = ""
e(a)
a = b
d = 5
a=d
e(a)