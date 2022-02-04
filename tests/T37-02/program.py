request = ""
uname = retrieve_uname(request)
clean_uname = cursor.sanitize(uname)
q = cursor.execute("SELECT pass FROM users WHERE user='%s'" % clean_uname)
