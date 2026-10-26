import argparse

import json
import requests

from pathlib import Path


def validate_domain(domain):

    if not domain and not domain.strip():
        raise argparse.ArgumentTypeError (
            "Domain must not be empty or contain surrounding whitespace"
        )

    if "://" in domain or "/" in domain or ":" in domain:
        raise argparse.ArgumentTypeError (
            "Provide domain name only, no scheme, port or path needed"
        )
    return domain

def parse_response(base_url, domain, ouput):
    params = {
        "q" : f"%.{domain}",
        "output" : "json"
    }

    try:
        response = requests.get(base_url, params=params, timeout=10)
        print(response.status_code)
        response.raise_for_status()

        data = response.json()

        if not data:
            print(f"Error: {base_url} returned an empty response")

        output_file = ouput
        output_file.write_text(
            response.text,
            encoding="utf-8"
        )

        print(f"Success, retrieved {len(data)} records")
        print(f"Resonse saved to {ouput}")

    except requests.exceptions.HTTPError as error:
        print("HTTP error occured:", error)
    except requests.exceptions.RequestException as error:
        print("A request error occured:", error)
    except json.JSONDecodeError as error:
        print(f"Error: {base_url} returned a response that is not a valid JSON file")

def get_args(argv=None):

    parser = argparse.ArgumentParser(description="API reconnnaissance tool")
    parser.add_argument(
        "--domain", 
        help="Provide a domain to parse", 
        required=True, 
        type=validate_domain
    )

    return parser.parse_args(argv)
   

def main():
    raw_response_path = Path("raw") / "crtsh-response.json"

    args = get_args()
    base_url = "https://crt.sh"

    domain = args.domain
    validate_domain(domain)
    parse_response(base_url, domain, raw_response_path)

    with open(raw_response_path, "r") as file:
        data = json.load(file)
   
if __name__ == "__main__":
    main()