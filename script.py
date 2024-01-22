import os
import random
import re
import namesgenerator
import argparse

base_directory = './logs/seroius03161/archive_log'
output_directory = './logs/anonymized_logs2'

endpoint_pattern = r'\b[^\/\s]+\/(?![0-9])[^\/\s]+(?:\/(?![0-9])[^\/\s]+)?'
ip_pattern = r'\b\d{1,3}(?:\.\d{1,3}){2,}\b'
timestamps = r'(\d{4}:\d{2}:\d{2}:\d{2})|(\d{2}:\d{2}:\d{2}[,\.]\d{3})'
user_id_pattern_general = r'\s[a-z][a-z0-9]{4,19}\s'
user_id_pattern_httpd = r'-\s[a-z][a-z0-9]{4,19}\s'
user_id_pattern_gc = r'-\s[a-z][a-z0-9_-]{4,19}\s'
user_id_pattern_sshd = r'\s[a-z0-9][a-z0-9]{4,19}\s'

exclude_extensions = ['.gz', '.md5', '.sha1', '.sha256', '.zip']

def anonymize_endpoint(match):
    original_endpoint = match.group(0)
    parts = original_endpoint.strip('/').split('/')
    anonymized_parts = []
    for part in parts:
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


def anonymize_ip(match):
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

def anonymize_timestamps(match):
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

def anonymize_user_id_general(match):
    original_user_id = match.group(0)
    if original_user_id in lookup_table:
        anonymized_user_id = lookup_table[original_user_id]
    else:
        anonymized_user_id = namesgenerator.get_random_name()
        lookup_table[original_user_id] = anonymized_user_id

    return ' ' + anonymized_user_id + ' ' 

def anonymize_user_id_httpd(match):
    original_user_id = match.group(0)
    if original_user_id in lookup_table:
        anonymized_user_id = lookup_table[original_user_id]
    else:
        anonymized_user_id = namesgenerator.get_random_name()
        lookup_table[original_user_id] = anonymized_user_id

    return '- ' + anonymized_user_id + ' ' 

def anonymize_user_line(line, filename):
    if 'httpd' in filename:
        line = re.sub(user_id_pattern_httpd, anonymize_user_id_httpd, line)
    elif 'sshd' in filename:
        line = re.sub(user_id_pattern_sshd, anonymize_user_id_general, line)
    elif 'gc.log' in filename:
        line = re.sub(user_id_pattern_gc, anonymize_user_id_httpd, line)
    else:
        line = re.sub(user_id_pattern_general, anonymize_user_id_general, line)
    return line

def randomize_numbers(number, isIp = False):
    num_len = len(str(number))
    lower_bound = 10**(num_len - 1)
    if (isIp):
        upper_bound = min(255, (10**num_len - 1))
    else:
        upper_bound = 10**num_len - 1
    if num_len == 1:
        lower_bound = 0

    return random.randint(lower_bound, upper_bound)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Anonymize log files. Anonymized files and their lookup tables are storedd in the `anonymized-logs` folder")
    parser.add_argument('--ip', action='store_true', help='Only Anonymize IP Addresses')
    parser.add_argument('--timestamps', action='store_true', help='Only Anonymize IP Addresses')
    parser.add_argument('--endpoint', action='store_true', help='Only Anonymize Endpoints')
    parser.add_argument('--user', action='store_true', help='Only Anonymize User IDs')

    args = parser.parse_args()

    os.makedirs(output_directory, exist_ok=True)
    for filename in os.listdir(base_directory):
        if not filename.endswith(tuple(exclude_extensions)):
            input_file_path = os.path.join(base_directory, filename)
            output_file_path = os.path.join(output_directory, f'anonymized_{filename}')
            lookup_file_path = os.path.join(output_directory, f'lookup_table_{filename}.txt')
            lookup_table = {}

            with open(input_file_path, 'r') as input_file, open(output_file_path, 'w') as output_file:
                for line in input_file:
                    if args.ip:
                        line = re.sub(ip_pattern, anonymize_ip, line)
                    if args.timestamps:
                        line = re.sub(timestamps, anonymize_timestamps, line)
                    if args.endpoint:
                        line = re.sub(endpoint_pattern, anonymize_endpoint, line)
                    if args.user:
                        line = anonymize_user_line(line, filename)
                    if not (args.ip or args.timestamps or args.endpoint or args.user):
                        line = re.sub(ip_pattern, anonymize_ip, line)
                        line = re.sub(endpoint_pattern, anonymize_endpoint, line)
                        line = anonymize_user_line(line, filename)
                    output_file.write(line)
                    

            with open(lookup_file_path, 'w') as lookup_file:
                for original_endpoint, anonymized_endpoint in lookup_table.items():
                    lookup_file.write(f'{anonymized_endpoint} -> {original_endpoint}\n')

            print(f'Logs in {filename} anonymized and saved to {output_file_path}')
            print(f'Lookup table for {filename} saved to {lookup_file_path} \n')