# spy 🕵️
`spy` is a (security) python tool to detect vulnerabilities in Django applications.

Developed within the scope of SSof @ IST | 2021/2022.

## How it works
Load AST from JSON file passed as argument, load list of vulnerability patterns, parse the tree whilst trying to find a match with the patterns and a link between a source and a sink

## Running
```bash
$ cd src
$ python3 main.py <program.json> <patterns.json>
```

This creates an output file in `src/output/`, under the name `<program>.output.json`.
Currently, we also support a mass testing mode using the examples provided by the teacher. By running:
```bash
$ python3 main.py -t <N>
```
we execute `<N>` tests, sequentially, from the simplest `1a` example up until `9`. Then, we compare the outputs and produce relevant messages. **Important to note** how due to numbering of the vulnerabilities found, false mismatches sometimes occur.

## Supported Features
We support the analysis of the mandatory constructs `Assign`, `Expr`, `If` and `While`. Moreover, we also check for sanitization flows that might occur therein.

## Known Issues
None :) 
