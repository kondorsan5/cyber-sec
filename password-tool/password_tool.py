import argparse
from password_validator import PasswordValidator

def getArgs(argv=None):
    parser = argparse.ArgumentParser(description="Password validator")
    parser.add_argument("--min-length", help="Set minimum password legnth", type=int, default=12)
    parser.add_argument("--file", help="Validate passwords from a file.")
    parser.add_argument("--config", type=str, default="config.json")
    args = parser.parse_args(argv)
    return args 
          



def main():
    validator = PasswordValidator()

    args = getArgs()

    file = open(args.file, 'r')
    
    for password in file:
        validator.validate_password(password)
    file.close()

if __name__== "__main__":
    main()