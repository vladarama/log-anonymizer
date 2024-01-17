import os
import random
import re
import namesgenerator
import argparse

base_directory = './logs/seroius03161/archive_log'
output_directory = './logs/anonymized_logs2'
lookup_table = {}

endpoint_pattern = r'\b[^\/\s]+\/(?![0-9])[^\/\s]+(?:\/(?![0-9])[^\/\s]+)?'
ip_pattern = r'\b\d{1,3}(?:\.\d{1,3}){2,}\b'
user_id_pattern = r'- ([a-zA-Z_\-][a-zA-Z0-9_\-]*)\s'

exclude_extensions = ['.gz', '.md5', '.sha1', '.sha256', '.zip']

parser = argparse.ArgumentParser(description="Anonymize log files. Anonymized files and their lookup tables are storedd in the `anonymized-logs` folder")
parser.add_argument('--ip', action='store_true', help='Only Anonymize IP Addresses')
parser.add_argument('--endpoint', action='store_true', help='Only Anonymize Endpoints')
parser.add_argument('--user', action='store_true', help='Only Anonymize User IDs')

args = parser.parse_args()

os.makedirs(output_directory, exist_ok=True)

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
            anonymized_part = str(random.randint(0, 255))
            anonymized_ip_parts.append(anonymized_part)
        anonymized_ip = ".".join(anonymized_ip_parts)
        lookup_table[original_ip] = anonymized_ip

    return anonymized_ip

def anonymize_user_id(match):
    original_user_id = match.group(1)
    if original_user_id in lookup_table:
        anonymized_user_id = lookup_table[original_user_id]
    else:
        anonymized_user_id = namesgenerator.get_random_name()
        lookup_table[original_user_id] = anonymized_user_id

    return '- ' + anonymized_user_id + ' ' 


for filename in os.listdir(base_directory):
    if not filename.endswith(tuple(exclude_extensions)):
        input_file_path = os.path.join(base_directory, filename)
        output_file_path = os.path.join(output_directory, f'anonymized_{filename}')
        lookup_file_path = os.path.join(output_directory, f'lookup_table_{filename}.txt')

        with open(input_file_path, 'r') as input_file, open(output_file_path, 'w') as output_file:
            for line in input_file:
                if args.ip:
                    line = re.sub(ip_pattern, anonymize_ip, line)
                if args.endpoint:
                    line = re.sub(endpoint_pattern, anonymize_endpoint, line)
                if args.user:
                    line = re.sub(user_id_pattern, anonymize_user_id, line)
                if not (args.ip or args.endpoint or args.user):
                    line = re.sub(ip_pattern, anonymize_ip, line)
                    line = re.sub(endpoint_pattern, anonymize_endpoint, line)
                    line = re.sub(user_id_pattern, anonymize_user_id, line)
                output_file.write(line)
                

        with open(lookup_file_path, 'w') as lookup_file:
            for original_endpoint, anonymized_endpoint in lookup_table.items():
                lookup_file.write(f'{anonymized_endpoint} -> {original_endpoint}\n')

        print(f'Logs in {filename} anonymized and saved to {output_file_path}')
        print(f'Lookup table for {filename} saved to {lookup_file_path}')
