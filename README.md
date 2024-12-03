# log-analysis-assignment
Python script for analyzing server logs

## Overview

This Python script is designed to parse and analyze log files, focusing on extracting key information such as the number of requests per IP address, the most accessed endpoints, and suspicious activity based on failed login attempts. The script then saves the analysis results to a CSV file and outputs them to the console.

## Features

- **IP Request Count**: Counts the number of requests made by each IP address.
- **Endpoint Access**: Tracks the number of accesses to each endpoint (GET/POST requests).
- **Suspicious Activity Detection**: Identifies suspicious activity based on failed login attempts (HTTP status code `401`), allowing you to set a threshold for detecting malicious behavior.
- **CSV Export**: Saves the results in a CSV file (`log_analysis_results.csv`).
- **Console Output**: Displays the results in a human-readable format.
- **New Section - Suspicious Activity Under Threshold**: Now includes detection of suspicious activity for failed login attempts that are below the defined threshold.

## Requirements

To run this script, you need to have Python installed on your system along with the following libraries:

- `pandas` - For handling data and generating CSV files.
- `re` - For using regular expressions to extract data from the logs.
- `collections` - To efficiently count occurrences using `defaultdict`.

### Install Required Libraries

If you don't have the required libraries installed, you can install them using pip:

```bash
pip install pandas
```

## Setup

1. Clone this repository or download the `log_analysis.py` script.
2. Ensure you have access to a log file you want to analyze. This script expects log files in the standard web server log format.
3. Set up the Python environment where you have `pandas` installed, or use a virtual environment.

## Usage

### Running the Script

1. Open the `log_analysis.py` file and update the `log_file` variable to point to your log file.

   ```python
   log_file = "path_to_your_log_file.log"
   ```

2. Define a threshold for suspicious activity. For example, setting `threshold = 10` means that the script will flag any IP address with more than 10 failed login attempts as suspicious.

   ```python
   threshold = 10
   ```

3. Run the script. The results will be displayed on the console and saved to a CSV file (`log_analysis_results.csv`).

   ```bash
   python log_analysis.py
   ```

### Input File Format

This script assumes the log file is in a format similar to the following: (*CHECK "sample.log"*)

```
192.168.1.1 - - [12/Dec/2023:06:25:13 +0000] "GET /index.html HTTP/1.1" 200 1234
192.168.1.2 - - [12/Dec/2023:06:26:01 +0000] "POST /login HTTP/1.1" 401 2345
192.168.1.1 - - [12/Dec/2023:06:27:20 +0000] "GET /dashboard HTTP/1.1" 200 6789
```

- **IP address**: The IP address of the client making the request.
- **Endpoint**: The endpoint being accessed (e.g., `/index.html`, `/login`).
- **HTTP Status Code**: This script looks specifically for the `401` status code to track failed login attempts.

### Output

#### CSV File

The analysis results will be saved to `log_analysis_results.csv`, containing the following sections:

1. **Requests per IP**: A list of IP addresses and the number of requests they made.
2. **Most Accessed Endpoint**: The endpoint that was accessed the most, along with its access count.
3. **Suspicious Activity (Above Threshold)**: A list of IP addresses with failed login attempts exceeding the threshold.
4. **Suspicious Activity (Under Threshold)**: A list of IP addresses with failed login attempts under the threshold.

   <img width="179" alt="image" src="https://github.com/user-attachments/assets/49249396-b4c5-463c-88b1-e685b72ca5a9">


#### Console Output

The console will display the results in a readable format:

1. **Requests per IP**: A table of IP addresses and their request counts.
2. **Most Accessed Endpoint**: Displays the endpoint that has been accessed the most.
3. **Suspicious Activity Detected (Above Threshold)**: If any IP addresses have failed login attempts exceeding the threshold, they will be listed.
4. **Suspicious Activity Detected (Under Threshold)**: Displays the IP addresses with failed login attempts under the threshold.

<img width="461" alt="image" src="https://github.com/user-attachments/assets/80888f8e-bc19-4beb-ad50-a7eaff369ff7">




### Example Output

#### Console

```
Requests per IP:
IP Address     Request Count
192.168.1.1    3
192.168.1.2    1

Most Frequently Accessed Endpoint:
GET /index.html (Accessed 1 times)

Suspicious Activity Detected (Failed Login Attempts > Threshold):
IP Address     Failed Login Attempts
192.168.1.2    15

Suspicious Activity Detected (Under Threshold):
IP Address     Failed Login Attempts
192.168.1.1    5
```

#### CSV

```csv
IP Address,Request Count
192.168.1.1,3
192.168.1.2,1

Most Accessed Endpoint, Access Count
//GET /index.html, 1

Suspicious Activity Detected (Failed Login Attempts > 10), Failed Login Attempts
192.168.1.2, 15

Suspicious Activity Detected (Under Threshold), Failed Login Attempts
192.168.1.1, 5
```

## Customization

You can adjust the following parameters in the script:

- **Threshold**: Set the number of failed login attempts that should be flagged as suspicious. For example, setting `threshold = 10` will flag IPs with more than 10 failed logins.
- **Log File Path**: Update the `log_file` variable to point to your actual log file.


**Thank You!!**
