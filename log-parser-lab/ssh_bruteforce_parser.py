import re
import json
import csv

import pandas as pd

from collections import Counter
from pathlib import Path

report = {
    "filename" : None,
    "danger_threshold" : 0,
    "analyzed_logs" : 0,
    "failed_login_logs" : 0, 
    "matched_logs" : 0,
    "unmatched_logs" : 0,
    "omitted_logs" : 0,
    "unique_ips" : 0,
    "ip_attempts_total" : {},
    "ips_over_threshold" : [],
    "ips_ico" : [],
    "ips_crossreferenced_ico" : [],
    "ips_ico_cross_over_threshold" : [],
    "note": (
        "This report is an analytical signal, "
        "not automatic confirmation of a security incident"
    )
}

web_report = {
    "ip_404" : {},
    "path_404" : {},
    "status_count" : {}
}

threshold = 3
ip_pattern = re.compile(r"\d+\.\d+\.\d+\.\d+")
http_method = re.compile(r"")

def process_file(log_path, analyzer):
    if not log_path.exists():
            raise FileExistsError ("Log file doesn't exist or is not a regular file")
    else:
        try:
            with log_path.open('r', encoding="utf-8") as lines:
               analyzer(lines)
            
        except OSError as error:
            print(f"Error reading log file: {error}")

        except UnicodeDecodeError as error:
            print(f"Error decoding log file: {error}")

def sort_counter(counter):
    if counter:
        sorted_counter = dict(counter.most_common())
        return sorted_counter
    
    else:
        print("Invalid counter")

def analyze_log(lines):
    counter = Counter()

    for line in lines:
        report["analyzed_logs"] += 1

        if "Failed password" in line:
            match = ip_pattern.search(line)
            report["failed_login_logs"] += 1

            if match:
                report["matched_logs"] += 1
                ip_address = match.group(0)
                counter[ip_address] += 1
            else:
                report["unmatched_logs"] += 1

        else:
            report["omitted_logs"] += 1

    report["unique_ips"] = len(counter)

    sorted_counter = sort_counter(counter)
    
    for ip, attempts in sorted_counter.items():
        if  attempts > threshold:
            report["ips_over_threshold"].append(ip)
        report["ip_attempts_total"].update({ip : attempts})

def analyze_ioc(lines):
    for ioc_ip in lines:
        if not ioc_ip.strip():
            continue
        report["ips_ico"].append(ioc_ip.strip())
        for ip in report["ip_attempts_total"]:
           
            if ip == ioc_ip.strip():
                report["ips_crossreferenced_ico"].append(ip)

                if report["ip_attempts_total"].get(ip) > threshold:
                    report["ips_ico_cross_over_threshold"].append(ip)

def analyze_web_sample(lines):
    ip_404_counter = Counter()
    path_404_counter = Counter()
    status_counter = Counter()

    for line in lines:
        parts = line.split('"')
        
        prefix = parts[0].split()
        request = parts[1].split()
        response = parts[2].split()
        
        ip = prefix[0]
        method = request[0]
        status = response[0]
        path = request[1]
        user_agent = parts[5]

        
        if status == '404':
            ip_404_counter[ip] += 1
            path_404_counter[path] += 1
            status_counter[status] += 1

    web_report["ip_404"] = dict(ip_404_counter)
    web_report["path_404"] = dict(path_404_counter)
    web_report["status_count"] = dict(status_counter)


def output_json_report(report_path, report):
    try: 
        with open(report_path, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=2)
    except (OSError, TypeError, ValueError, IsADirectoryError) as error:
        print(f"Error saving JSON file: {error}")

def output_csv_report(report_path, report):
    try:
        with open(report_path, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow([
                "source_ip",
                "failed_logins",
                "alert",
                "ico_over_threshold"
            ])

            ico_ips = set(report["ips_ico_cross_over_threshold"])

            for ip, count in report["ip_attempts_total"].items():
                writer.writerow([
                    ip,
                    count,
                    count > threshold,
                    ip in ico_ips,
                ])

    except (OSError, TypeError, ValueError, IsADirectoryError) as error:
            print(f"Error saving CSV file: {error}")                    


def output_web_csv_report(output_path):
    try:
        with open(output_path, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow([
                "path",
                "404_count",
            ])

            for path, count in web_report["path_404"].items():
                writer.writerow([
                    path,
                    count
                ])

    except (OSError, TypeError, ValueError, IsADirectoryError) as error:
            print(f"Error saving CSV file: {error}")   

def pandas_report_log(report_path, report_output):
    df = pd.read_csv(report_path)
    
    print("\nFirst Records")
    print(df.head())
    
    print("\nColumns")
    print(df.columns)
    
    print("\nSort values - although already sorted in the report")
    print(df.sort_values("failed_logins", ascending=False))
    
    print("\nTop 10 IP's")
    print(df.head(10))
    
    print("\nFiltered records - with alert")
    alerts = df[df["alert"] == True]
    print(alerts)
    alerts.to_csv(report_output)   

def main():
    log_path = Path("data") / "auth-sample.log"
    ioc_path = Path("data") / "ioc-ips.txt"
    web_log_path = Path("data") / "apache-sample.log" 
 
    json_report_path = Path("output") / "ssh-bruteforce_report.json"
    csv_report_path = Path("output") / "ssh-bruteforce_report.csv"
    ioc_alert_path = Path("output") / "ioc-alerts.csv"
    web_report_path = Path("output") / "web-report-path.csv"

    report["filename"] = str(json_report_path.resolve())
    report["danger_threshold"] = threshold

    process_file(log_path, analyze_log)
    process_file(ioc_path, analyze_ioc)


    output_json_report(json_report_path, report)
    output_csv_report(csv_report_path, report)
        
    pandas_report_log(csv_report_path, ioc_alert_path)

    # Web File analaysis
    process_file(web_log_path, analyze_web_sample)
    output_web_csv_report(web_report_path)
    df = pd.read_csv(web_report_path)
    sorted_df = df.sort_values("404_count", ascending=False)
    print("\nTOP10 paths with 404 status")
    print(sorted_df.head(10))

if __name__ == "__main__":
    main()