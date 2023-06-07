# Rapidast Results Parser

This small python script is used in order to generate a .csv file that will help the offering teams to intrepet the Rapidast results

## Usage

The usage is very simple, just run the script with --file as argument: 

```
python3 rapidast_parser.py --file zap-report.json
```

If no --file is selected, "zap-report.json" by default will be used.

## Disclaimer

In order to avoid discolosing sensitive information, the instances columns just show the endpoint but won't show any header. To see this information, look at the original results file.

