import re
import pandas as pd
from collections import defaultdict

# Function to parse the log file and analyze various data points
def analyze_logs(log_file, threshold=10):
    # Dictionaries to store counts for IP addresses, endpoints, and failed login attempts
    ip_counts = defaultdict(int)
    endpoint_counts = defaultdict(int)
    failed_logins = defaultdict(int)
    
    # Regular expressions for extracting data from the log file
    ip_pattern = r'^(\S+)'  # Extracts the IP address
    endpoint_pattern = r'"(?:GET|POST) (\S+)'  # Extracts the endpoint for GET/POST requests
    failed_login_pattern = r'401'  # Looks for failed login attempts (HTTP status code 401)
    
    # Open and read the log file line by line
    with open(log_file, 'r') as file:
        for line in file:
            # Extract the IP address from each line
            ip_match = re.match(ip_pattern, line)
            if ip_match:
                ip = ip_match.group(1)
                ip_counts[ip] += 1

            # Extract the endpoint (GET/POST request)
            endpoint_match = re.search(endpoint_pattern, line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_counts[endpoint] += 1

            # Check if there was a failed login attempt (HTTP 401)
            if re.search(failed_login_pattern, line):
                ip_match = re.match(ip_pattern, line)
                if ip_match:
                    ip = ip_match.group(1)
                    failed_logins[ip] += 1

    # Sort the results in descending order of count
    sorted_ip_counts = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    sorted_endpoint_counts = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)
    sorted_failed_logins = sorted(failed_logins.items(), key=lambda x: x[1], reverse=True)

    # Create a DataFrame for requests per IP
    df_requests_per_ip = pd.DataFrame(sorted_ip_counts, columns=['IP Address', 'Request Count'])

    # Find the most frequently accessed endpoint
    if sorted_endpoint_counts:
        most_accessed_endpoint = sorted_endpoint_counts[0]
        most_accessed_endpoint_str = f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)"
    else:
        most_accessed_endpoint_str = "No data available"

    # Identify suspicious activity with failed login attempts above the threshold
    suspicious_activity_above_threshold = []
    for ip, failed_count in sorted_failed_logins:
        if failed_count > threshold:
            suspicious_activity_above_threshold.append([ip, failed_count])
    
    df_suspicious_above_threshold = pd.DataFrame(suspicious_activity_above_threshold, columns=['IP Address', 'Failed Login Attempts'])

    # Identify suspicious activity with failed login attempts under the threshold
    suspicious_activity_under_threshold = []
    for ip, failed_count in sorted_failed_logins:
        if 0 < failed_count <= threshold:
            suspicious_activity_under_threshold.append([ip, failed_count])

    df_suspicious_under_threshold = pd.DataFrame(suspicious_activity_under_threshold, columns=['IP Address', 'Failed Login Attempts'])

    # Define output file path for CSV
    output_file_csv = 'log_analysis_results.csv'

    # Save the results to a CSV file
    df_requests_per_ip.to_csv(output_file_csv, index=False)

    # Add other sections (Most Accessed Endpoint, Suspicious Activity) to the CSV
    with open(output_file_csv, 'a') as f:
        # Writing Most Accessed Endpoint
        f.write("\nMost Accessed Endpoint, Access Count\n")
        f.write(f"//{most_accessed_endpoint[0]}, {most_accessed_endpoint[1]}\n")
        
        # Writing Suspicious Activity Above Threshold
        f.write("\nSuspicious Activity Detected (Failed Login Attempts > 10), Failed Login Attempts\n")
        for ip, failed_count in suspicious_activity_above_threshold:
            f.write(f"{ip}, {failed_count}\n")
        
        # Writing Suspicious Activity Under Threshold
        f.write("\nSuspicious Activity Detected (Under Threshold), Failed Login Attempts\n")
        for ip, failed_count in suspicious_activity_under_threshold:
            f.write(f"{ip}, {failed_count}\n")

    # Print the analysis results to the console
    print("\nRequests per IP:")
    print(df_requests_per_ip.to_string(index=False))  # Display without index

    print("\nMost Frequently Accessed Endpoint:")
    print(most_accessed_endpoint_str)  # Display in custom format for most accessed endpoint

    if suspicious_activity_above_threshold:
        print("\nSuspicious Activity Detected (Failed Login Attempts > Threshold):")
        print(df_suspicious_above_threshold.to_string(index=False))  # Display without index
    else:
        print("\nSuspicious Activity Detected (Failed Login Attempts > Threshold):")
        print("No suspicious activity detected above the threshold.")

    print("\nSuspicious Activity Detected (Under Threshold):")
    if df_suspicious_under_threshold.empty:
        print("No suspicious activity detected under the threshold.")
    else:
        print(df_suspicious_under_threshold.to_string(index=False))  # Display without index

    # Print a confirmation that results have been saved
    print("\nResults saved to a CSV file named log_analysis_results.csv")

    return output_file_csv

# Example usage
log_file = "sample.log"  # Replace with the path to your actual log file
threshold = 10  # Set your threshold for detecting suspicious activity
output_file_csv = analyze_logs(log_file, threshold)

output_file_csv
