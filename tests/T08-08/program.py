a = b()
c = b()
d = b()
e = b()
f = b()
g = b()
h = func()
i = func()
if cond:
    d = c
    if cond:
        c = d
        if cond:
            e = c
            if cond:
                a = e
                if cond:
                    g = a
                    if cond:
                        h = g
                        if cond:
                            i = h    
                        else:
                            h = i
                    else:
                        g = h
                else:
                    a = g
            else:
                e = a
        else:
            c = e
    else:
        d = c
else:
    c = d
t(h, i)