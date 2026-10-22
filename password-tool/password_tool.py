import argparse
import json

from pathlib import Path
from password_validator import PasswordValidator

DEFAULT_POLICY = {
  "min_length": 16,
  "require_lower": True,
  "require_upper": True,
  "require_digit": False,
  "require_special": True,
  "special_chars": "!@#$%^&*"
}

def get_args(argv=None):
    parser = argparse.ArgumentParser(description="Password validator")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--password", help="Provide password as a CLI argument. Test purposes only. Cannot be used with --file", default=None)
    group.add_argument("--file", help="Validate passwords from a file. Cannot be used with --password")
    parser.add_argument("--min-length", help="Set minimum password legnth", type=int, default=None)
    parser.add_argument("--config", help = "Provide a path to a configuration file.", type=str)
    parser.add_argument("--verbose", help =  "Print all erros for each password", action="store_true")
    args = parser.parse_args(argv)
    return args

def build_policy(args, config):
    policy = DEFAULT_POLICY.copy()
    policy.update(config)

    if args.min_length is not None:
        policy["min_length"] = args.min_length
    validate_config(policy)

    return policy

def load_config(config_path):
    if config_path is None:
        local_config = Path("config.json")

        if not local_config.exists():
            return {}

        config_path = local_config

    try:
        with config_path.open("r", encoding="utf-8") as file:
            config = json.load(file)

    except FileNotFoundError:
        raise ValueError(
            f"Configuration file '{config_path}' doesn't exist."
        ) from None

    except json.JSONDecodeError as error:
        raise ValueError(
            f"Incorrect format of JSON file: '{config_path}' "
            f"(Line {error.lineno}, column {error.colno})."
        ) from None

    except UnicodeDecodeError:
        raise ValueError(
            f"'{config_path}' is not UTF-8 encoded."
        ) from None

    except OSError:
        raise ValueError(
            f"Can't find file: '{config_path}'."
        ) from None
    
    validate_config(config)

    return config

def validate_config(config):
    if not isinstance(config, dict):
        raise ValueError("This is not a valid configuration for a Json file - expected dict")

    if "min_length" not in config:
        raise ValueError("Missing 'min_length in configuration")

    if not isinstance(config["min_length"], int):
        raise ValueError("'min_length' should be an integer")

    if config["min_length"] < 1:
        raise ValueError("'min_length' must be positive")

    for key in ("require_lower", "require_upper", "require_digit", "require_special"):
        if key in config and not isinstance(config[key], bool):
            raise ValueError(f"{key} must be a boolean")

def print_report(arg, count, problems):
    if arg == True:
        if len(problems) == 0:
            print(f"Password #{count}")
            print("Password OK")
            print("--------------------")
        else:
            print(f"Password #{count}")
            print("Password NOK")
            for problem in problems:
                print(problem)
            print("--------------------")
    elif arg == False:
        if len(problems) == 0:
            print(f"Password #{count}")
            print("Password OK")
        else:
            print(f"Password #{count}")
            print("Password NOK")

def main():
    # args = get_args()
    # validator = PasswordValidator()

    # if args.config:
    #     config = load_config(args.config)
    #     build_policy(config)



    args = get_args()
    config = load_config(args.config)
    policy = build_policy(args, config)
    validator = PasswordValidator(policy["min_length"],
                                  policy["require_lower"],
                                  )
    
    if args.file:
        with open(args.file, 'r', encoding="utf-8") as pass_file:
            count = 1
            for password in pass_file:
                validator.validate_password(password)
                print_report(args.verbose, count, validator.problems)
                count += 1
    if args.password:
        validator.validate_password(args.password)
        print_report(args.verbose, 1, validator.problems)

if __name__== "__main__":
    main()