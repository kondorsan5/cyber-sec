import argparse
import csv
import json
import requests
import time

from pathlib import Path

def validate_domain(domain):

    if not domain or domain != domain.strip():
        raise argparse.ArgumentTypeError (
            "Domain must not be empty or contain surrounding whitespace"
        )

    if "://" in domain or "/" in domain or ":" in domain:
        raise argparse.ArgumentTypeError (
            "Provide domain name only, no scheme, port or path needed"
        )
    return domain


def get_args(argv=None):

    parser = argparse.ArgumentParser(description="API reconnnaissance tool")
    parser.add_argument(
        "--domain", 
        help="Provide a domain to parse", 
        required=True, 
        type=validate_domain
    )

    return parser.parse_args(argv)

def get_response(base_url, domain):
    params = {
        "q" : f"%.{domain}",
        "output" : "json"
    }

    response = requests.get(base_url, params=params, timeout=10)
    print(response.status_code)
    response.raise_for_status()
    data = response.json()

    return data

    
def extract_subdomains(entries, domain):
    if not isinstance(entries, list):
        raise ValueError("Error: ")
    domain = domain.strip().lower().rstrip(".")
    names = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        value = entry.get("name_value", "")
        if not isinstance(value, str):
            continue
        for raw in value.splitlines():
            name = raw.strip().lower().removeprefix("*.").rstrip(".")
            if name.endswith("." + domain):
                names.add(name)
    return sorted(names)

def test_subdomains(scheme, domain):
    
    domain_log = {
        "subdomain" : domain,
        "scheme" : "",
        "status_code" : None, 
        "result" : "",
        "url" : "",

        }

    security_log = {
        "subdomain" : domain,
        "url" : "",
        "status_code" : None, 
        "Strict-Transport-Security" : "",
        "Content-Security-Policy" : "",
        "X-Frame-Options" : "",
        "X-Content-Type-Options" : "", 
        "Referrer-Policy" : "",
        "Permissions-Policy" : "",
    }
    
    names = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]

    try:
        domain_log["scheme"] = scheme
        response = requests.get(f"{scheme}://{domain}", timeout=3)
        domain_log["url"] = response.url 
        domain_log["status_code"] = response.status_code
        security_log["status_code"]
        domain_log["result"] = "responded"

        for name in names:
            if name in response.headers:
                domain_log[name] = "present"
            else:
                domain_log[name] = "missing"
        
    except requests.exceptions.ConnectionError as error:
        domain_log["result"] = "no_response"
        print("Connection error: ", error)
    except requests.exceptions.Timeout as error:
        domain_log["result"] = "no_response"
        print("Timeout:", error)
    except requests.exceptions.RequestException as error:
        domain_log["result"] = "no_response"
        print("Request error: ", error)

    for name in names:
        domain_log[name] = "not_checked"

    return domain_log, security_log

def open_json(path):
    try:
        with open(path, "r", encoding="utf-8") as file:
            entries = json.load(file)
    except (OSError, TypeError, ValueError, IsADirectoryError, json.JSONDecodeError) as error:
        print(f"Error saving JSON file: {error}")
    return entries    

def output_json(path, data):
    try:
        with open(path, 'w', encoding="utf-8") as file:
            json.dump(data, file)

    except (OSError, TypeError, ValueError, IsADirectoryError, json.JSONDecodeError) as error:
           print(f"Error saving JSON file: {error}")

def output_csv(file_path, data, fieldnames):
    try:
        with open(file_path, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames, extrasaction="ignore")

            writer.writeheader()
            writer.writerows(data)
    except (TypeError, ValueError, IsADirectoryError) as error:
           print(f"Error saving CSV file: {error}")

def main() -> int:
    args = get_args()
    base_url = "https://crt.sh"
    domain = args.domain

    raw_folder = Path("raw")
    raw_folder.mkdir(parents=True, exist_ok=True)

    output_folder = Path("output")
    output_folder.mkdir(parents=True, exist_ok=True)

    raw_response_path =  raw_folder / "crtsh-response.json"
    subdomains_csv_path = output_folder / "subdomains.txt"
    subdomains_txt_path = output_folder / "subdomains.csv"
    http_validation_csv_path = output_folder / "http-validation.csv"
    security_headers_path = output_folder / "security-headers.csv"

    try:
        response = get_response(base_url, domain)

    except requests.exceptions.HTTPError as error:
        print("HTTP error occured:", error)
        return 1

    except json.JSONDecodeError as error:
        print("JSON format error: ", error)
        return 1
    
    except requests.exceptions.RequestException as error:
        print("A request error occured:", error)
        return 1

    output_json(raw_response_path, response)
    subdomains_list = extract_subdomains(response, domain)

    with open(subdomains_txt_path, 'w', encoding="utf-8") as file:
        file.write(subdomains_list)

    

    http_validations_list = []
    security_list = []

    for subdomain in subdomains_list:
        http_validation, security_validation = test_subdomains("https",subdomain)
        http_validations_list.append(http_validation)
        security_list.append(security_validation)
        
        http_validation, security_validation = test_subdomains("http",subdomain)
        http_validations_list.append(http_validation)
        security_list.append(security_validation)

    http_validation_fieldnames = ["subdomain", "scheme", "status_code", "result"]
    security_headers_fieldnames = ["subdomain", "status_code", "url", "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]
    output_csv(http_validation_csv_path, http_validations_list , http_validation_fieldnames)
    output_csv(security_headers_path, http_validations_list, security_headers_fieldnames)
    
    return 0

if __name__ == "__main__":
   raise SystemExit(main())