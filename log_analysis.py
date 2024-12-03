import re
import csv
from collections import Counter, defaultdict


def parse_log(file_path):
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            # Extraction for IP address
            ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
            if ip_match:
                ip = ip_match.group()
                ip_requests[ip] += 1

            # Extraction for endpoint
            endpoint_match = re.search(r'\"[A-Z]+\s(\/\S*)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_requests[endpoint] += 1

            # Detect failed login attempts
            if '401' in line or 'Invalid credentials' in line:
                if ip_match:
                    failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins


def save_to_csv(ip_requests, endpoint, endpoint_count, failed_logins, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.most_common():
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([endpoint, endpoint_count])

        # Write suspicious activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in failed_logins.items():
            writer.writerow([ip, count])


def main():
    log_file = 'sample.log'
    output_csv = 'log_analysis_results.csv'
    threshold = 10

    # Parse the log file
    ip_requests, endpoint_requests, failed_logins = parse_log(log_file)

    # Identify most accessed endpoint
    most_accessed_endpoint, max_access_count = endpoint_requests.most_common(1)[0]

    # Identify suspicious activity
    flagged_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}

    # Display results
    print("Requests per IP:")
    for ip, count in ip_requests.most_common():
        print(f"{ip}: {count}")

    print("\nMost Accessed Endpoint:")
    print(f"{most_accessed_endpoint} (Accessed {max_access_count} times)")

    print("\nSuspicious Activity Detected:")
    if flagged_ips:
        for ip, count in flagged_ips.items():
            print(f"{ip}: {count} failed login attempts")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    save_to_csv(ip_requests, most_accessed_endpoint, max_access_count, failed_logins, output_csv)
    print(f"\nResults saved to {output_csv}")


if __name__ == "__main__":
    main()
