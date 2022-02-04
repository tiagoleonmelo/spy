untainted="safe"

if 10 > 100:
    untainted=get
else:
    untainted=escape_string(get)
    

execute(untainted)
