#! /usr/bin/env python3

"""
Log Anonymizer

Anonymizes log timestamp, IPs and endpoints.
"""
import os
import random
import re
import argparse
import argparse
import namesgenerator
import tqdm

__author__ = "Vlad Arama"
__copyright__ = "Copyright 2024, Ericsson"
__credits__ = ["Vlad Arama"]
__license__ = "MIT"

# General Regex Patterns
IP_PATTERN = r"\b\d{1,3}(?:\.\d{1,3}){2,}\b"
TIMESTAMP_PATTERN = r"(\d{4}:\d{2}:\d{2}:\d{2})|(\d{2}:\d{2}:\d{2}[,\.]\d{3})"
ENDPOINT_PATTERN = r"\b[^\/\s]+\/(?![0-9])[^\/\s]+(?:\/(?![0-9])[^\/\s]+)?"
USER_ID_PATTERN = r"\s[a-z][a-z0-9]{4,19}\s"
IP_PATTERN = r"\b\d{1,3}(?:\.\d{1,3}){2,}\b"
TIMESTAMP_PATTERN = r"(\d{4}:\d{2}:\d{2}:\d{2})|(\d{2}:\d{2}:\d{2}[,\.]\d{3})"
ENDPOINT_PATTERN = r"\b[^\/\s]+\/(?![0-9])[^\/\s]+(?:\/(?![0-9])[^\/\s]+)?"
USER_ID_PATTERN = r"\s[a-z][a-z0-9]{4,19}\s"

# Specific Regex Patterns
HTTPD_PATTERN = r"\s*(\S+)\s*(\S*)\s*\-\s(\S+)\s\[(\S+\s*\S+)\]\s\"(\S+)\s+(\S+)\s(\S+)\"\s(\d+)\s(\S+)\s(\S+)\s\"(.*)\""
SSHD_PATTERN = r"\[(\d.*)\]\s+(\S+)\s+(\S+)\s+(\S+)\s+((([A-Z]+)\sFROM\s+(.*))|(([A-Z]+))|((AUTH FAILURE)\sFROM\s(\S+)\s(.*))|((.+)\s+(\S+)\s+(\S+)\s+(\S+)))"
HA_PROXY_PATTERN = r'^(\w+ \d+ \S+) (\S+) (\S+)\[(\d+)\]: (\S+):(\d+) \[(\S+)\] (\S+) (\S+) (\S+) (\S+) (\S+) *(\S+) (\S+) (\S+)(?: (\S+) (\S+) \{([^}]*)\} \{([^}]*)\} "(\S+) ([^"]+) (\S+)")? *$'
HTTPD_PATTERN = r"\s*(\S+)\s*(\S*)\s*\-\s(\S+)\s\[(\S+\s*\S+)\]\s\"(\S+)\s+(\S+)\s(\S+)\"\s(\d+)\s(\S+)\s(\S+)\s\"(.*)\""
SSHD_PATTERN = r"\[(\d.*)\]\s+(\S+)\s+(\S+)\s+(\S+)\s+((([A-Z]+)\sFROM\s+(.*))|(([A-Z]+))|((AUTH FAILURE)\sFROM\s(\S+)\s(.*))|((.+)\s+(\S+)\s+(\S+)\s+(\S+)))"
HA_PROXY_PATTERN = r'^(\w+ \d+ \S+) (\S+) (\S+)\[(\d+)\]: (\S+):(\d+) \[(\S+)\] (\S+) (\S+) (\S+) (\S+) (\S+) *(\S+) (\S+) (\S+)(?: (\S+) (\S+) \{([^}]*)\} \{([^}]*)\} "(\S+) ([^"]+) (\S+)")? *$'

FILES_TO_EXCLUDE = [".gz", ".md5", ".sha1", ".sha256", ".zip"]

FILES_TO_EXCLUDE = [".gz", ".md5", ".sha1", ".sha256", ".zip"]


def anonymize_ip(matched_pattern) -> str:
    """
    Takes a regex match, representing a line in any type of log file.
    Returns an anonymized IP address.

    """
    original_ip = matched_patterned_pattern.group(0)
    if original_ip in lookup_table:
        anonymized_ip = lookup_table[original_ip]
    else:
        ip_parts = original_ip.split(".")
        ip_parts = original_ip.split(".")
        anonymized_ip_parts = []
        for part in ip_parts:
            anonymized_part = str(randomize_numbers(part, True))
            anonymized_ip_parts.append(anonymized_part)
        anonymized_ip = ".".join(anonymized_ip_parts)
        lookup_table[original_ip] = anonymized_ip

    return anonymized_ip


def anonymize_ip_ha(matched_pattern) -> str:
    """
    Takes a regex match, representing a line in an HA Proxy log file.
    Returns a line with all of the IP addresses and their ports anonymized.

    """
    original_ip = matched_patterned_pattern.group(5)
    original_port = matched_patterned_pattern.group(6)

    if original_ip in lookup_table:
        anonymized_ip = lookup_table[original_ip]
    else:
        ip_parts = original_ip.split(".")
        ip_parts = original_ip.split(".")
        anonymized_ip_parts = [str(randomize_numbers(part, True)) for part in ip_parts]
        anonymized_ip = ".".join(anonymized_ip_parts)
        lookup_table[original_ip] = anonymized_ip

    if original_port in lookup_table:
        anonymized_port = lookup_table[original_port]
    else:
        anonymized_port = str(randomize_numbers(original_port, False))
        lookup_table[original_port] = anonymized_port

    return "".join(
        [
            matched_pattern.string[: matched_pattern.start(5)],
            anonymized_ip,
            matched_pattern.string[matched_pattern.end(5) : matched_pattern.start(6)],
            anonymized_port,
            matched_pattern.string[matched_pattern.end(6) :],
        ]
    )

    return "".join(
        [
            matched_pattern.string[: matched_pattern.start(5)],
            anonymized_ip,
            matched_pattern.string[matched_pattern.end(5) : matched_pattern.start(6)],
            anonymized_port,
            matched_pattern.string[matched_pattern.end(6) :],
        ]
    )


def anonymize_ip_line(line: str, filename: str) -> str:
    """
    Takes a specific line from a file and its filename.
    Takes a specific line from a file and its filename.
    Returns the line with all of the IP addresses anonymized.


    """
    if "ha" in filename:
        line = re.sub(HA_PROXY_PATTERN, anonymize_ip_ha, line)
    if "ha" in filename:
        line = re.sub(HA_PROXY_PATTERN, anonymize_ip_ha, line)
    else:
        line = re.sub(IP_PATTERN, anonymize_ip, line)

    return line.rstrip() + "\n"
        line = re.sub(IP_PATTERN, anonymize_ip, line)

    return line.rstrip() + "\n"


def anonymize_timestamps(matched_pattern) -> str:
    """
    Takes a regex match, representing a line in any type of log file.
    Returns an anonymized timestamp that has the same length as the original one.
    This will break monotonicity.
    This will break monotonicity.

    """
    original_timestamp = matched_pattern.group(0)
    if original_timestamp in lookup_table:
        anonymized_ip = lookup_table[original_timestamp]
    original_timestamp = matched_pattern.group(0)
    if original_timestamp in lookup_table:
        anonymized_ip = lookup_table[original_timestamp]
    else:
        ip_parts = original_timestamp.split(":")
        ip_parts = original_timestamp.split(":")
        anonymized_ip_parts = []
        for part in ip_parts:
            anonymized_part = str(randomize_numbers(part))
            anonymized_ip_parts.append(anonymized_part)
        anonymized_ip = ":".join(anonymized_ip_parts)
        lookup_table[original_timestamp] = anonymized_ip
        lookup_table[original_timestamp] = anonymized_ip

    return anonymized_ip


def anonymize_user_id(user_id:str) ->str:
    """
    Takes a user id or any sensitive name and anonymizes it.

    """
    if user_id in lookup_table:
        anonymized_user_id = lookup_table[user_id]
    else:
        anonymized_user_id = namesgenerator.get_random_name()
        lookup_table[user_id] = anonymized_user_id


    return anonymized_user_id


def anonymize_user_id_general(matched_pattern:str)->str:
    """
    Takes a regex match, representing a line in any type of log file.
    Returns a randomly generated user id.

    """
    original_user_id = matched_patterned_pattern.group(0)
    anonymized_user_id = anonymize_user_id(original_user_id)

    return " " + anonymized_user_id + " "

    return " " + anonymized_user_id + " "


def anonymize_user_id_httpd_sshd(matched_pattern)->str:
    """
    Takes a regex match, representing a line in an HTTP or SSH log file.
    Returns a line with all of the user information anonymized.

    """
    original_user_id = matched_pattern.group(3)
    if original_user_id == "-":
        return matched_pattern.group(0)
    original_user_id = matched_pattern.group(3)
    if original_user_id == "-":
        return matched_pattern.group(0)
    anonymized_user_id = anonymize_user_id(original_user_id)

    return "".join(
        [
            matched_pattern.string[: matched_pattern.start(3)],
            anonymized_user_id,
            matched_pattern.string[matched_pattern.end(3) :],
        ]
    )

    return "".join(
        [
            matched_pattern.string[: matched_pattern.start(3)],
            anonymized_user_id,
            matched_pattern.string[matched_pattern.end(3) :],
        ]
    )


def anonymize_sensitive_info_ha(matched_pattern)->str:
    """
    Takes a regex match, representing a line in an HA Proxy log file.
    Returns a line with all of the sensitive information anonymized.

    """
    # Validate that sensitive information is present
    if not (matched_pattern.group(18) and matched_pattern.group(19)):
        return matched_pattern.group(0)
    if not (matched_pattern.group(18) and matched_pattern.group(19)):
        return matched_pattern.group(0)

    original_info1 = matched_pattern.group(18)
    original_info2 = matched_pattern.group(19)
    original_info1 = matched_pattern.group(18)
    original_info2 = matched_pattern.group(19)
    anonymized_info1 = anonymize_user_id(original_info1)
    anonymized_info2 = anonymize_user_id(original_info2)

    return "".join(
        [
            matched_pattern.string[: matched_pattern.start(18)],
            anonymized_info1,
            matched_pattern.string[matched_pattern.end(18) : matched_pattern.start(19)],
            anonymized_info2,
            matched_pattern.string[matched_pattern.end(19) :],
        ]
    )

    return "".join(
        [
            matched_pattern.string[: matched_pattern.start(18)],
            anonymized_info1,
            matched_pattern.string[matched_pattern.end(18) : matched_pattern.start(19)],
            anonymized_info2,
            matched_pattern.string[matched_pattern.end(19) :],
        ]
    )


def anonymize_user_line(line:str, filename:str)->str:
    """
    Takes a specific line from a file and its filename.
    Takes a specific line from a file and its filename.
    Returns the line with all of the user information and sensitive information anonymized.


    """
    if "httpd" in filename:
        line = re.sub(HTTPD_PATTERN, anonymize_user_id_httpd_sshd, line)
    elif "sshd" in filename:
        line = re.sub(SSHD_PATTERN, anonymize_user_id_httpd_sshd, line)
    elif "ha" in filename:
        line = re.sub(HA_PROXY_PATTERN, anonymize_sensitive_info_ha, line)
    if "httpd" in filename:
        line = re.sub(HTTPD_PATTERN, anonymize_user_id_httpd_sshd, line)
    elif "sshd" in filename:
        line = re.sub(SSHD_PATTERN, anonymize_user_id_httpd_sshd, line)
    elif "ha" in filename:
        line = re.sub(HA_PROXY_PATTERN, anonymize_sensitive_info_ha, line)
    else:
        line = re.sub(USER_ID_PATTERN, anonymize_user_id_general, line)

    return line.rstrip() + "\n"
        line = re.sub(USER_ID_PATTERN, anonymize_user_id_general, line)

    return line.rstrip() + "\n"


def anonymize_endpoint(original_endpoint)->str:
    """
    Takes an endpoint and returns its anonymized version.

    """
    endpoint_parts = original_endpoint.strip("/").split("/")
    endpoint_parts = original_endpoint.strip("/").split("/")
    anonymized_parts = []
    for part in endpoint_parts:
        if part in lookup_table:
            anonymized_part = lookup_table[part]
        else:
        else:
            anonymized_part = namesgenerator.get_random_name()
            lookup_table[part] = anonymized_part
        anonymized_parts.append(anonymized_part)

    if original_endpoint.startswith("/"):
        anonymized_endpoint = "/" + "/".join(anonymized_parts)

    if original_endpoint.startswith("/"):
        anonymized_endpoint = "/" + "/".join(anonymized_parts)
    else:
        anonymized_endpoint = "/".join(anonymized_parts)
        anonymized_endpoint = "/".join(anonymized_parts)

    return anonymized_endpoint


def anonymize_endpoint_general(match)->str:
    """
    Takes a regex match, representing a line in any type of log file.
    Returns the anonymized endpoint.
    """
    original_endpoint = match.group(0)
    return anonymize_endpoint(original_endpoint)


def anonymize_endpoint_httpd(match)->str:
    """
    Takes a regex match, representing a line in an HTTP log file.
    Returns the anonymized endpoint.


    """
    original_endpoint = match.group(6)
    anonymized_endpoint = anonymize_endpoint(original_endpoint)

    return "".join(
        [
            match.string[: match.start(6)],
            anonymized_endpoint,
            match.string[match.end(6) :],
        ]
    )

    return "".join(
        [
            match.string[: match.start(6)],
            anonymized_endpoint,
            match.string[match.end(6) :],
        ]
    )


def anonymize_endpoint_sshd(match)->str:
    """
    Takes a regex match, representing a line in an SSH log file.
    Returns the anonymized endpoint.
    """
    original_endpoint = match.group(5)
    parts = original_endpoint.split(" ", 1)
    endpoint_part = parts[0].strip("/").split("/")
    remaining_string = parts[1] if len(parts) > 1 else ""
    parts = original_endpoint.split(" ", 1)
    endpoint_part = parts[0].strip("/").split("/")
    remaining_string = parts[1] if len(parts) > 1 else ""

    if len(endpoint_part) < 2:
        return match.group(0)

    anonymized_endpoint = anonymize_endpoint(original_endpoint)
    anonymized_endpoint += " " + remaining_string if remaining_string else ""
    anonymized_endpoint += " " + remaining_string if remaining_string else ""

    return "".join(
        [
            match.string[: match.start(5)],
            anonymized_endpoint,
            match.string[match.end(5) :],
        ]
    )

    return "".join(
        [
            match.string[: match.start(5)],
            anonymized_endpoint,
            match.string[match.end(5) :],
        ]
    )


def anonymize_endpoint_ha(match)->str:
    """
    Takes a regex match, representing a line in an HA Proxy log file.
    Returns a line with all of the endpoints anonymized.
    """
    original_endpoint = match.group(9)
    anonymized_endpoint = anonymize_endpoint(original_endpoint)
    anonymized_line = "".join(
        [
            match.string[: match.start(9)],
            anonymized_endpoint,
            match.string[match.end(9) :],
        ]
    )
    anonymized_line = "".join(
        [
            match.string[: match.start(9)],
            anonymized_endpoint,
            match.string[match.end(9) :],
        ]
    )

    if match.group(21):
    if match.group(21):
        original_endpoint2 = match.group(21)
        anonymized_endpoint2 = anonymize_endpoint(original_endpoint2)
        anonymized_line = "".join(
            [
                match.string[: match.start(9)],
                anonymized_endpoint,
                match.string[match.end(9) : match.start(21)],
                anonymized_endpoint2,
                match.string[match.end(21) :],
            ]
        )
        anonymized_line = "".join(
            [
                match.string[: match.start(9)],
                anonymized_endpoint,
                match.string[match.end(9) : match.start(21)],
                anonymized_endpoint2,
                match.string[match.end(21) :],
            ]
        )

    return anonymized_line


def anonymize_endpoint_line(line, filename)->str:
    """
    Takes a specific line from a file and its filename.
    Returns the line with all of the endpoints anonymized.


    """
    if "httpd" in filename:
        line = re.sub(HTTPD_PATTERN, anonymize_endpoint_httpd, line)
    elif "sshd" in filename:
        line = re.sub(SSHD_PATTERN, anonymize_endpoint_sshd, line)
    elif "ha" in filename:
        line = re.sub(HA_PROXY_PATTERN, anonymize_endpoint_ha, line)
    if "httpd" in filename:
        line = re.sub(HTTPD_PATTERN, anonymize_endpoint_httpd, line)
    elif "sshd" in filename:
        line = re.sub(SSHD_PATTERN, anonymize_endpoint_sshd, line)
    elif "ha" in filename:
        line = re.sub(HA_PROXY_PATTERN, anonymize_endpoint_ha, line)
    else:
        line = re.sub(ENDPOINT_PATTERN, anonymize_endpoint_general, line)
    return line.rstrip() + "\n"

        line = re.sub(ENDPOINT_PATTERN, anonymize_endpoint_general, line)
    return line.rstrip() + "\n"


def randomize_numbers(number, is_ip_address:bool=False)->str:
def randomize_numbers(number, is_ip_address:bool=False)->str:
    """
    Takes a number and a flag to indicate if the given number is part of an IP address.
    Returns a random number that has the same length as the original one. If the number is part of an IP address,
    the function will return a random number between 0 and 255 (inclusive)

    """
    num_len = len(str(number))
    lower_bound = 10 ** (num_len - 1)
    if is_ip_address:
    lower_bound = 10 ** (num_len - 1)
    if is_ip_address:
        upper_bound = min(255, (10**num_len - 1))
    else:
        upper_bound = 10**num_len - 1
    if num_len == 1:
        lower_bound = 0

    return random.randint(lower_bound, upper_bound)


def count_lines(file_path:str)->int:
    c = 0
    with open(file_path) as file:
        while True:
            chunk = file.read(10 ** 7)
            if chunk == "":
                return c
            c += chunk.count("\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Anonymize log files. Anonymized files and their lookup tables are storedd in the `anonymized-logs` folder"
    )
    parser.add_argument(
        "input_directory",
        type=str,
        help="Directory containing the log files to be anonymized",
    )
    parser.add_argument(
        "output_directory",
        type=str,
        help="Directory where the anonymized files will be stored",
    )
    parser.add_argument("--ip", action="store_true", help="Only Anonymize IP Addresses")
    parser.add_argument(
        "--endpoint", action="store_true", help="Only Anonymize Endpoints"
    )
    parser.add_argument("--user", action="store_true", help="Only Anonymize User IDs")
    parser.add_argument(
        "--timestamps", action="store_true", help="Only Anonymize Timestamps"
    )
    parser = argparse.ArgumentParser(
        description="Anonymize log files. Anonymized files and their lookup tables are storedd in the `anonymized-logs` folder"
    )
    parser.add_argument(
        "input_directory",
        type=str,
        help="Directory containing the log files to be anonymized",
    )
    parser.add_argument(
        "output_directory",
        type=str,
        help="Directory where the anonymized files will be stored",
    )
    parser.add_argument("--ip", action="store_true", help="Only Anonymize IP Addresses")
    parser.add_argument(
        "--endpoint", action="store_true", help="Only Anonymize Endpoints"
    )
    parser.add_argument("--user", action="store_true", help="Only Anonymize User IDs")
    parser.add_argument(
        "--timestamps", action="store_true", help="Only Anonymize Timestamps"
    )

    args = parser.parse_args()

    base_directory = args.input_directory
    base_directory = args.input_directory
    output_directory = args.output_directory
    os.makedirs(output_directory, exist_ok=True)

    for file_name in tqdm.tqdm(os.listdir(base_directory), unit=' Files'):
        if not file_name.lower().endswith(tuple(FILES_TO_EXCLUDE)):
            input_file_path = os.path.join(base_directory, file_name)
            output_file_path = os.path.join(output_directory, f"anonymized_{file_name}")
            lookup_file_path = os.path.join(
                output_directory, f"lookup_table_{file_name}.txt"
            )
            lookup_table = {}
            line_count = count_lines(file_path=file_name)
            with open(
                file=input_file_path, mode="r", encoding="utf-8"
            ) as input_file, open(
                file=output_file_path, mode="w", encoding="utf-8"
            ) as output_file:
                for current_line in tqdm.tqdm(iterable=input_file,unit=' Lines', total=line_count):
                    if args.ip:
                        current_line = anonymize_ip_line(current_line, file_name)
                        current_line = anonymize_ip_line(current_line, file_name)
                    if args.endpoint:
                        current_line = anonymize_endpoint_line(current_line, file_name)
                        current_line = anonymize_endpoint_line(current_line, file_name)
                    if args.user:
                        current_line = anonymize_user_line(current_line, file_name)
                        current_line = anonymize_user_line(current_line, file_name)
                    if args.timestamps:
                        re_match = re.match(TIMESTAMP_PATTERN, current_line)
                        if re_match:
                            new_ts = anonymize_timestamps(re_match)
                            if new_ts:
                                current_line = re.sub(TIMESTAMP_PATTERN, new_ts, current_line)
                        re_match = re.match(TIMESTAMP_PATTERN, current_line)
                        if re_match:
                            new_ts = anonymize_timestamps(re_match)
                            if new_ts:
                                current_line = re.sub(TIMESTAMP_PATTERN, new_ts, current_line)
                    if not (args.ip or args.timestamps or args.endpoint or args.user):
                        current_line = anonymize_ip_line(current_line, file_name)
                        current_line = anonymize_endpoint_line(current_line, file_name)
                        current_line = anonymize_user_line(current_line, file_name)

                    output_file.write(current_line)

            with open(file=lookup_file_path, mode="w", encoding="utf-8") as lookup_file:
                        current_line = anonymize_ip_line(current_line, file_name)
                        current_line = anonymize_endpoint_line(current_line, file_name)
                        current_line = anonymize_user_line(current_line, file_name)

                    output_file.write(current_line)

            with open(file=lookup_file_path, mode="w", encoding="utf-8") as lookup_file:
                for original_data, anonymized_data in lookup_table.items():
                    lookup_file.write(f"{anonymized_data} -> {original_data}\n")

            print(f"Logs in {file_name} anonymized and saved to {output_file_path}")
            print(f"Lookup table for {file_name} saved to {lookup_file_path} \n")
                    lookup_file.write(f"{anonymized_data} -> {original_data}\n")

            print(f"Logs in {file_name} anonymized and saved to {output_file_path}")
            print(f"Lookup table for {file_name} saved to {lookup_file_path} \n")
