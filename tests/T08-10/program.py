a = b()
c = a
while a != "":
    while c != "":
        if c == a:
            r = d()
        else:
            r = f()
        a = r
    if a == "teste":
        p = d()
    else:
        p = f()
    c = p
t(a, c)