import os
import random
import re
import namesgenerator
import argparse

# General Regex Patterns
ip_pattern = r'\b\d{1,3}(?:\.\d{1,3}){2,}\b'
timestamps_pattern = r'(\d{4}:\d{2}:\d{2}:\d{2})|(\d{2}:\d{2}:\d{2}[,\.]\d{3})'
endpoint_pattern = r'\b[^\/\s]+\/(?![0-9])[^\/\s]+(?:\/(?![0-9])[^\/\s]+)?'
user_id_pattern = r'\s[a-z][a-z0-9]{4,19}\s'

# Specific Regex Patterns
httpd_pattern = r'\s*(\S+)\s*(\S*)\s*\-\s(\S+)\s\[(\S+\s*\S+)\]\s\"(\S+)\s+(\S+)\s(\S+)\"\s(\d+)\s(\S+)\s(\S+)\s\"(.*)\"'
sshd_pattern = r'\[(\d.*)\]\s+(\S+)\s+(\S+)\s+(\S+)\s+((([A-Z]+)\sFROM\s+(.*))|(([A-Z]+))|((AUTH FAILURE)\sFROM\s(\S+)\s(.*))|((.+)\s+(\S+)\s+(\S+)\s+(\S+)))'
ha_proxy_pattern = r'^(\w+ \d+ \S+) (\S+) (\S+)\[(\d+)\]: (\S+):(\d+) \[(\S+)\] (\S+) (\S+) (\S+) (\S+) (\S+) *(\S+) (\S+) (\S+)(?: (\S+) (\S+) \{([^}]*)\} \{([^}]*)\} "(\S+) ([^"]+) (\S+)")? *$'

files_to_exclude = ['.gz', '.md5', '.sha1', '.sha256', '.zip']

def anonymize_ip(match):
    """
    Takes a regex match, representing a line in any type of log file.
    Returns an anonymized IP address.

    """
    original_ip = match.group(0)
    if original_ip in lookup_table:
        anonymized_ip = lookup_table[original_ip]
    else:
        ip_parts = original_ip.split('.')
        anonymized_ip_parts = []
        for part in ip_parts:
            anonymized_part = str(randomize_numbers(part, True))
            anonymized_ip_parts.append(anonymized_part)
        anonymized_ip = ".".join(anonymized_ip_parts)
        lookup_table[original_ip] = anonymized_ip

    return anonymized_ip

def anonymize_ip_ha(match):
    """
    Takes a regex match, representing a line in an HA Proxy log file.
    Returns a line with all of the IP addresses and their ports anonymized.

    """
    original_ip = match.group(5)
    original_port = match.group(6)

    if original_ip in lookup_table:
        anonymized_ip = lookup_table[original_ip]
    else:
        ip_parts = original_ip.split('.')
        anonymized_ip_parts = [str(randomize_numbers(part, True)) for part in ip_parts]
        anonymized_ip = ".".join(anonymized_ip_parts)
        lookup_table[original_ip] = anonymized_ip

    if original_port in lookup_table:
        anonymized_port = lookup_table[original_port]
    else:
        anonymized_port = str(randomize_numbers(original_port, False))
        lookup_table[original_port] = anonymized_port

    return ''.join([match.string[:match.start(5)], anonymized_ip, match.string[match.end(5):match.start(6)], anonymized_port, match.string[match.end(6):]])

def anonymize_ip_line(line, filename):
    """
    Takes a specific line from a file and its filename. 
    Returns the line with all of the IP addresses anonymized.
    
    """
    if 'ha' in filename:
        line = re.sub(ha_proxy_pattern, anonymize_ip_ha, line)
    else:
        line = re.sub(ip_pattern, anonymize_ip, line)

    return line.rstrip() + '\n'

def anonymize_timestamps(match):
    """
    Takes a regex match, representing a line in any type of log file.
    Returns an anonymized timestamp that has the same length as the original one.

    """
    original_ip = match.group(0)
    if original_ip in lookup_table:
        anonymized_ip = lookup_table[original_ip]
    else:
        ip_parts = original_ip.split(':')
        anonymized_ip_parts = []
        for part in ip_parts:
            anonymized_part = str(randomize_numbers(part))
            anonymized_ip_parts.append(anonymized_part)
        anonymized_ip = ":".join(anonymized_ip_parts)
        lookup_table[original_ip] = anonymized_ip

    return anonymized_ip

def anonymize_user_id(user_id):
    """
    Takes a user id or any sensitive name and anonymizes it.

    """
    if user_id in lookup_table:
        anonymized_user_id = lookup_table[user_id]
    else:
        anonymized_user_id = namesgenerator.get_random_name()
        lookup_table[user_id] = anonymized_user_id
    
    return anonymized_user_id
    
def anonymize_user_id_general(match):
    """
    Takes a regex match, representing a line in any type of log file.
    Returns a randomly generated user id.

    """
    original_user_id = match.group(0)
    anonymized_user_id = anonymize_user_id(original_user_id)

    return ' ' + anonymized_user_id + ' ' 

def anonymize_user_id_httpd_sshd(match):
    """
    Takes a regex match, representing a line in an HTTP or SSH log file.
    Returns a line with all of the user information anonymized.

    """
    original_user_id = match.group(3)
    if original_user_id == '-':
        return match.group(0)
    anonymized_user_id = anonymize_user_id(original_user_id)

    return ''.join([match.string[:match.start(3)], anonymized_user_id, match.string[match.end(3):]])

def anonymize_sensitive_info_ha(match):
    """
    Takes a regex match, representing a line in an HA Proxy log file.
    Returns a line with all of the sensitive information anonymized.

    """
    # Validate that sensitive information is present
    if match.group(18) == None or match.group(19) == None:
        return match.group(0)

    original_info1 = match.group(18)
    original_info2 = match.group(19)
    anonymized_info1 = anonymize_user_id(original_info1)
    anonymized_info2 = anonymize_user_id(original_info2)

    return ''.join([match.string[:match.start(18)], anonymized_info1, match.string[match.end(18):match.start(19)], anonymized_info2, match.string[match.end(19):]])

def anonymize_user_line(line, filename):
    """
    Takes a specific line from a file and its filename. 
    Returns the line with all of the user information and sensitive information anonymized.
    
    """
    if 'httpd' in filename:
        line = re.sub(httpd_pattern, anonymize_user_id_httpd_sshd, line)
    elif 'sshd' in filename:
        line = re.sub(sshd_pattern, anonymize_user_id_httpd_sshd, line)
    elif 'ha' in filename:
        line = re.sub(ha_proxy_pattern, anonymize_sensitive_info_ha, line)
    else:
        line = re.sub(user_id_pattern, anonymize_user_id_general, line)

    return line.rstrip() + '\n'

def anonymize_endpoint(original_endpoint):
    """
    Takes an endpoint and returns its anonymized version.

    """
    endpoint_parts = original_endpoint.strip('/').split('/')
    anonymized_parts = []
    for part in endpoint_parts:
        if part in lookup_table:
            anonymized_part = lookup_table[part]
        else: 
            anonymized_part = namesgenerator.get_random_name()
            lookup_table[part] = anonymized_part
        anonymized_parts.append(anonymized_part)
    
    if original_endpoint.startswith('/'):
        anonymized_endpoint = '/' + '/'.join(anonymized_parts)
    else:
        anonymized_endpoint = '/'.join(anonymized_parts)

    return anonymized_endpoint

def anonymize_endpoint_general(match):
    """
    Takes a regex match, representing a line in any type of log file.
    Returns the anonymized endpoint.
    
    """
    original_endpoint = match.group(0)
    return anonymize_endpoint(original_endpoint)

def anonymize_endpoint_httpd(match):
    """
    Takes a regex match, representing a line in an HTTP log file.
    Returns the anonymized endpoint.
    
    """
    original_endpoint = match.group(6)
    anonymized_endpoint = anonymize_endpoint(original_endpoint)

    return ''.join([match.string[:match.start(6)], anonymized_endpoint, match.string[match.end(6):]])

def anonymize_endpoint_sshd(match):
    """
    Takes a regex match, representing a line in an SSH log file.
    Returns the anonymized endpoint.
    
    """
    original_endpoint = match.group(5)
    parts = original_endpoint.split(' ', 1)
    endpoint_part = parts[0].strip('/').split('/')
    remaining_string = parts[1] if len(parts) > 1 else ''

    if len(endpoint_part) < 2:
        return match.group(0)

    anonymized_endpoint = anonymize_endpoint(original_endpoint)
    anonymized_endpoint += ' ' + remaining_string if remaining_string else ''

    return ''.join([match.string[:match.start(5)], anonymized_endpoint, match.string[match.end(5):]])

def anonymize_endpoint_ha(match):
    """
    Takes a regex match, representing a line in an HA Proxy log file.
    Returns a line with all of the endpoints anonymized.

    """
    original_endpoint = match.group(9)
    anonymized_endpoint = anonymize_endpoint(original_endpoint)
    anonymized_line =  ''.join([match.string[:match.start(9)], anonymized_endpoint, match.string[match.end(9):]])

    if match.group(21) != None:
        original_endpoint2 = match.group(21)
        anonymized_endpoint2 = anonymize_endpoint(original_endpoint2)
        anonymized_line = ''.join([match.string[:match.start(9)], anonymized_endpoint, match.string[match.end(9):match.start(21)], anonymized_endpoint2, match.string[match.end(21):]])

    return anonymized_line

def anonymize_endpoint_line(line, filename):
    """
    Takes a specific line from a file and its filename. 
    Returns the line with all of the endpoints anonymized.
    
    """
    if 'httpd' in filename:
        line = re.sub(httpd_pattern, anonymize_endpoint_httpd, line)
    elif 'sshd' in filename:
        line = re.sub(sshd_pattern, anonymize_endpoint_sshd, line)
    elif 'ha' in filename:
        line = re.sub(ha_proxy_pattern, anonymize_endpoint_ha, line)
    else:
        line = re.sub(endpoint_pattern, anonymize_endpoint_general, line)
    return line.rstrip() + '\n'

def randomize_numbers(number, is_ip_address = False):
    """
    Takes a number and a flag to indicate if the given number is part of an IP address.
    Returns a random number that has the same length as the original one. If the number is part of an IP address,
    the function will return a random number between 0 and 255 (inclusive)

    """
    num_len = len(str(number))
    lower_bound = 10**(num_len - 1)
    if (is_ip_address):
        upper_bound = min(255, (10**num_len - 1))
    else:
        upper_bound = 10**num_len - 1
    if num_len == 1:
        lower_bound = 0

    return random.randint(lower_bound, upper_bound)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Anonymize log files. Anonymized files and their lookup tables are storedd in the `anonymized-logs` folder")
    parser.add_argument('input_directory', type=str, help='Directory containing the log files to be anonymized')
    parser.add_argument('output_directory', type=str, help='Directory where the anonymized files will be stored')
    parser.add_argument('--ip', action='store_true', help='Only Anonymize IP Addresses')
    parser.add_argument('--endpoint', action='store_true', help='Only Anonymize Endpoints')
    parser.add_argument('--user', action='store_true', help='Only Anonymize User IDs')
    parser.add_argument('--timestamps', action='store_true', help='Only Anonymize Timestamps')

    args = parser.parse_args()

    base_directory = args.input_directory 
    output_directory = args.output_directory
    os.makedirs(output_directory, exist_ok=True)

    for filename in os.listdir(base_directory):
        if not filename.endswith(tuple(files_to_exclude)):
            input_file_path = os.path.join(base_directory, filename)
            output_file_path = os.path.join(output_directory, f'anonymized_{filename}')
            lookup_file_path = os.path.join(output_directory, f'lookup_table_{filename}.txt')
            lookup_table = {}

            with open(input_file_path, 'r') as input_file, open(output_file_path, 'w') as output_file:
                for line in input_file:
                    if args.ip:
                        line = anonymize_ip_line(line, filename)
                    if args.endpoint:
                        line = anonymize_endpoint_line(line, filename)
                    if args.user:
                        line = anonymize_user_line(line, filename)
                    if args.timestamps:
                        line = re.sub(timestamps, anonymize_timestamps, line)
                    if not (args.ip or args.timestamps or args.endpoint or args.user):
                        line = anonymize_ip_line(line, filename)
                        line = anonymize_endpoint_line(line, filename)
                        line = anonymize_user_line(line, filename)
                    
                    output_file.write(line)
                    
            with open(lookup_file_path, 'w') as lookup_file:
                for original_data, anonymized_data in lookup_table.items():
                    lookup_file.write(f'{anonymized_data} -> {original_data}\n')

            print(f'Logs in {filename} anonymized and saved to {output_file_path}')
            print(f'Lookup table for {filename} saved to {lookup_file_path} \n')