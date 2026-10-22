# Password Tool

## Description

`password-tool` is an educational CLI tool for testing password strength against a simple policy.

The aim of the tool was to learn basic concepts of building a CLI tool.

## Requirments

- Python 3
- Virtual environment `venv`

## Environment setup

1. Utwórz środowisko wirtualne - Linux
    python3 -m venv venv
2. Aktywuj środowisko.
    source venv/bin/activate

## How to

Example usage:

- Validating a single password:
python3 password_tool.py --password password123

- Validating password list from a file:
python3 password_tool.py --file passwords-sample.txt

- Changing minimum password length policy:
python3 password_tool.py --file passwords-sample.txt --min-length 20

- Using own policy with 'config.json' file
python3 password_tool.py --file passwords-sample.txt --config /policy/config.json

- Controlling verbosity of the report:
python3 password_tool.py --verbose --file passwords-sample.txt

## CLI arguments

| Argument       | Description                        |
|---             |---                                 |
| `--min-length` | Minimum password length            |
| `--config`     | Path to custom policy JSON file    |
| `--password`   | Validate a single test password    |
| `--file`       | Validate passwords from a file     |
| `--verbose`    | Detailed report with missing policy|

## Policy configuration

Using --config allows to provide a custom policy by providing a path to the file.

'config.json' supports the following fields:
- "min_length" — minimum password length
- "require_lower" — check whether the password contains a lowercase letter
- "require_upper" — check whether the password contains an uppercase letter
- "require_digit" — check whether the password contains a digit
- "require_special" — check whether the password contains special characters
- "special_chars" — the set of special characters to check for

If no config path is provided the tool uses the local configuration file. 

In case CLI argument '--min-length' is used, it will overwrite the policy file.

## Safety

As a safety precaution do not use the tool in a production environment.

