while a < b:
    if a:
        k = a
    elif b:
        k = b
    elif c:
        k = c
    else:
        k = d
else:
    k = 1
sink(k)

#elifs inside a loop