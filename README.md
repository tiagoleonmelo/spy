# spy
`spy` is a (security) python tool to detect vulnerabilities in Django applications.

Developed within the scope of SSof @ IST | 2021/2022.

## How it works
Load AST from JSON file passed as argument, load list of vulnerability patterns, parse the tree whilst trying to find a match with the patterns and a link between a source and a sink

## Running
```bash
$ git clone git@github.com:tiagoleonmelo/spy.git # Cloning with SSH
$ cd src
$ python3 main.py slices/example.py patterns.json
```

## Backlog
* Currently ASTrees are being generated from source code. I couldn't find a package that converts JSON to ASTs, only source code to ASTs and ASTs to JSON. The input must be an AST JSON file.
* This works a lot like a compiler. We get an `ast`, and then `ast.visit()` it. I think the idea goes along the lines of implementing our own Parser, since we can subclass `ast.NodeVisitor` and override its methods. Check [src/visitor.py](https://github.com/tiagoleonmelo/spy/blob/main/src/visitor.py) and the [tutorial](https://greentreesnakes.readthedocs.io/en/latest/manipulating.html) dos stores.
* I think we can use `grep` for finding sinks in the AST input and then trace back to variables that taint it. If any of these variables was obtained with the sources that correspond to that entry in the vulnerability patterns input file, we flag the sink as unsafe.
* We must produce a JSON entry with this information for every vulnerability found. We also must find potential sanitization attemps that might already be in place (once again, I think we can do it with `grep`).
