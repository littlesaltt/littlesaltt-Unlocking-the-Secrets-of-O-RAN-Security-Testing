
import json
import os
import re

# 定義 JSON 文件的路徑
desktop_path = os.path.expanduser("~/Desktop")
json_file_path = os.path.join(desktop_path, "localhost.json")

# 加載 JSON 文件
try:
    with open(json_file_path, 'r') as f:
        data = json.load(f)
except (FileNotFoundError, json.JSONDecodeError) as e:
    print(f"加載 JSON 文件 {json_file_path} 時出錯: {e}")
    data = {}

# 提取 raw value
banner = data.get("banner", {})
raw_value = banner.get("raw", "")
if raw_value:
    print(f"Raw value: {raw_value}")
else:
    print("未找到 raw value。")


def extract_openssh_version(raw_value):
    pattern = r"OpenSSH_(\d+\.\d+)"
    match = re.search(pattern, raw_value)
    if match:
        version_str = match.group(1)
        major, minor = map(int, version_str.split('.'))
        return (major, minor)
    else:
        return None


def version_to_tuple(version_str):
    match = re.match(r'(\d+)\.(\d+)', version_str)
    if match:
        return (int(match.group(1)), int(match.group(2)))
    return None


def extract_versions_from_description(description):
    pattern = r"OpenSSH (\d+\.\d+)"
    matches = re.findall(pattern, description)
    return {version_to_tuple(match) for match in matches if version_to_tuple(match)}


def version_in_range(version, min_version, max_version):
    return min_version <= version < max_version


def filter_cve_by_openssh_version(cve_data, target_version):
    filtered_cves = []
    seen_cves = set()  # 用於跟踪已處理過的 CVE ID

    for item in cve_data:
        cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID', '')
        description = item.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value', '')
        versions_in_description = extract_versions_from_description(description)

        # Check if target version is listed
        if target_version in versions_in_description:
            if cve_id not in seen_cves:
                metrics = item.get('impact', {})
                base_severity = metrics.get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity', 'UNKNOWN')
                filtered_cves.append({'cve_id': cve_id, 'description': description, 'severity': base_severity})
                seen_cves.add(cve_id)
        else:
            # Check for "through" range in description
            range_pattern = r'OpenSSH (\d+)\.(\d+) through (\d+)\.(\d+)'
            range_match = re.search(range_pattern, description)
            if range_match:
                min_version = (int(range_match.group(1)), int(range_match.group(2)))
                max_version = (int(range_match.group(3)), int(range_match.group(4)))
                if version_in_range(target_version, min_version, max_version):
                    if cve_id not in seen_cves:
                        metrics = item.get('impact', {})
                        base_severity = metrics.get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity', 'UNKNOWN')
                        filtered_cves.append({'cve_id': cve_id, 'description': description, 'severity': base_severity})
                        seen_cves.add(cve_id)
            else:
                # Check for "before" versions
                before_versions = re.findall(r'OpenSSH.*?before (\d+\.\d+)', description)
                for before_version_str in before_versions:
                    before_version = version_to_tuple(before_version_str)
                    if before_version and before_version > target_version:
                        if cve_id not in seen_cves:
                            metrics = item.get('impact', {})
                            base_severity = metrics.get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity',
                                                                                                  'UNKNOWN')
                            filtered_cves.append(
                                {'cve_id': cve_id, 'description': description, 'severity': base_severity})
                            seen_cves.add(cve_id)
                        break  # Ensure each CVE is only added once

                # Check for "earliest affected version"
                earliest_version_match = re.search(r'earliest affected version is (\d+\.\d+)', description)
                if earliest_version_match:
                    earliest_version_str = earliest_version_match.group(1)
                    earliest_version = version_to_tuple(earliest_version_str)
                    if earliest_version and earliest_version > target_version:
                        continue  # Skip this CVE as it does not affect the target version

                # Check if description contains "OpenSSH" and configurations have version ranges
                if "OpenSSH" in description:
                    configurations = item.get('configurations', {})
                    nodes = configurations.get('nodes', [])
                    if nodes and isinstance(nodes, list):
                        cpe_match = nodes[0].get('cpe_match', [])
                        for match in cpe_match:
                            if match.get('vulnerable', False):
                                start_version = match.get('versionStartIncluding', '')
                                end_version = match.get('versionEndExcluding', '')
                                start_version_tuple = version_to_tuple(start_version)
                                end_version_tuple = version_to_tuple(end_version)
                                if start_version_tuple and end_version_tuple and version_in_range(target_version,
                                                                                                  start_version_tuple,
                                                                                                  end_version_tuple):
                                    if cve_id not in seen_cves:
                                        metrics = item.get('impact', {})
                                        base_severity = metrics.get('baseMetricV3', {}).get('cvssV3', {}).get(
                                            'baseSeverity', 'UNKNOWN')
                                        filtered_cves.append(
                                            {'cve_id': cve_id, 'description': description, 'severity': base_severity})
                                        seen_cves.add(cve_id)
                                    break  # Ensure each CVE is only added once

    return filtered_cves


# 處理版本資訊
version = extract_openssh_version(raw_value)
if version:
    print(f"Extracted version of OpenSSH: {version[0]}.{version[1]}")
else:
    print("OpenSSH version not found")
    version = (0, 0)

# 加載 CVE JSON 文件
cve_file_paths = [
    os.path.join(desktop_path, "nvdcve-1.1-2024.json"),
    os.path.join(desktop_path, "nvdcve-1.1-2023.json"),
    os.path.join(desktop_path, "nvdcve-1.1-2022.json"),
    os.path.join(desktop_path, "nvdcve-1.1-2021.json"),
    os.path.join(desktop_path, "nvdcve-1.1-2020.json")
]


def load_json_files(filepaths):
    json_data = []
    for filepath in filepaths:
        absolute_path = os.path.abspath(filepath)
        if os.path.exists(absolute_path):
            try:
                with open(absolute_path, 'r') as file:
                    data = json.load(file)
                    json_data.extend(data.get('CVE_Items', []))
            except (FileNotFoundError, json.JSONDecodeError) as e:
                print(f"加載 {filepath} 時出錯: {e}")
        else:
            print(f"文件未找到: {absolute_path}")
    return json_data


cve_data = load_json_files(cve_file_paths)

# 過濾 CVE 資料
filtered_cves = filter_cve_by_openssh_version(cve_data, version)
if filtered_cves:
    for cve in filtered_cves:
        cve_id = cve['cve_id']
        description = cve['description']
        severity = cve['severity']

        if severity == "LOW":
            print("(Low)\n"f"CVE ID: {cve_id}\nDescription: {description}\n")
        elif severity == "MEDIUM":
            print("(Medium)\n"f"CVE ID: {cve_id}\nDescription: {description}\n")
        elif severity == "HIGH":
            print("(High)\n"f"CVE ID: {cve_id}\nDescription: {description}\n")
        elif severity == "CRITICAL":
            print("(Critical)\n"f"CVE ID: {cve_id}\nDescription: {description}\n")
        else:
            print("(Unknown)\n"f"CVE ID: {cve_id}\nDescription: {description}\n")
        print("-----------------------")
else:
    print("未找到符合條件的 CVE。")
