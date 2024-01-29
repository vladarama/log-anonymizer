# Log Anonymizer

Log Anonymizer is a Python-based tool for anonymizing sensitive information in log files. It helps maintaining privacy by masking sensitive data such as IP addresses, user IDs, endpoints, timestamps and so on.
At the moment, the tool only supports HTTP, SSH and HA Proxy log formats. The Log Anonymizer can be used for other log formats, but complete anonymization might not occur, since the script might not be able to correctly identify sensitive information.

## Features
- Anonymize IP Addresses: Replaces original IP addresses with randomized ones, maintaining the same format.
- Anonymize User IDs: Replaces user IDs with randomly generated names.
- Anonymize Endpoints: Replaces original endpoints with their anonymized version, maintaining the same length.
- Anonymize Timestamps (optional): Replaces timestamps with their anonymized version while keeping the same structure.
- Selective Anonymization: Provides options to selectively anonymize only IPs, endpoints, user IDs, or timestamps (or any combination of them).
- Lookup Table Creation: Generates lookup tables mapping anonymized data back to the original data for reference.

## Requirements
- Python 3.x
- `namesgenerator` external library

## Installation
1 - Clone the repository or download the `log_anonymizer.py` file.

2 - Ensure Python 3.x is installed on your system.

3- Install the `namesgenerator` library by running `pip install namesgenerator` in your terminal.

## Usage
`python log_anonymizer.py <input_directory> <output_directory> [options]`

### Arguments
- input_directory: Directory containing the log files to be anonymized.
- output_directory: Directory where the anonymized files and lookup tables will be stored.
  
### Options
- --ip: Anonymize only IP addresses.
- --endpoint: Anonymize only endpoints.
- --user: Anonymize only user IDs.
- --timestamps: Anonymize only timestamps.

### Output
- Anonymized log files will be saved in the specified output directory.
- A lookup table for each file will be generated in the same output directory, mapping anonymized data to original data.

## Example
`python log_anonymizer.py /path/to/logs /path/to/output --ip --user`

This command will anonymize IP addresses and user IDs in log files located in `/path/to/logs` and save the anonymized logs to `/path/to/output`.
