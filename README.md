# Rapidast Results Parser

This small python script is used in order to generate a .csv file that will help the offering teams to intrepet the Rapidast results

## Usage

The options provided by the scripts are very simple:

```
usage: rapidast_parser.py [-h] [--file FILE] [--tool {zap,garak}]
                          [--output OUTPUT_DESTINATION]

Select file to parse.

optional arguments:
  -h, --help            show this help message and exit
  --file FILE           Select rapidast file result to parse (default: zap-
                        report.json)
  --tool {zap,garak}    Select tool whose file we want to parse
  --output OUTPUT_DESTINATION
                        Select name of results file (the extension should be
                        csv). If no file is specified, a default
                        parsed_results_<date>.csv file will be used.
```

The usage is very simple, just run the script with the desired-to-parse `--file` and the used `--tool` flags. For example:


```
python3 rapidast_parser.py --tool zap --file zap-report.json
```

or

```
python3 rapidast_parser.py --tool garak --file report-hitlog.jsonl
```

## GitHub Actions

In order to simplify the use of the script, we also provide a GitHub action that can be integrated into your repo to perform the parsing of the files automatically.
In order to make it work, you will need to use a token with write access and modify the secret name under the line

```
token: ${{secrets.GH_TOKEN}}
```

This action will create a new folder in your repo called `results` where these files will be uploaded. If you want to change the path, just use the `--output` parameter and specify it.

## Further improvements

This script can be further improved to help engineering teams simplify its use:

- Autodetection of used tool
- Removed redundancy between tools
- Multi-tool parsing

## Disclaimer

In order to avoid discolosing sensitive information, the instances columns just show the endpoint but won't show any header. To see this information, look at the original results file.

