import os
import csv
import yaml
import glob
import subprocess

# Initialize CSV file
csv_columns = ['file_name', 'expected_file_path', 'vulnerable_file_name', 'file_type', 'file_hash', 'link', 'hijacklib_link']
csv_file = "hijacklibs_list.csv"

# If in your environment, some workstations have a different drive letter (other than C:) you may want to modify this script accordingly
def replace_variables(path):
    path = path.replace("%LOCALAPPDATA%", 'C:\\Users\\*\\AppData\\Local')
    path = path.replace("%PROGRAMFILES%", 'C:\\Program Files')
    path = path.replace("%VERSION%", '*')
    path = path.replace("%SYSTEM32%", 'C:\\Windows\\System32')
    path = path.replace("%SYSWOW64%", 'C:\\Windows\\SysWOW64')
    path = path.replace("%USERPROFILE%", 'C:\\Users\\*')
    path = path.replace("%WINDIR%", 'C:\\Windows')
    path = path.replace("%PROGRAMDATA%", 'C:\\ProgramData')
    return path

# Clone HijackLibs repository
repo_url = "https://github.com/wietze/HijackLibs"
repo_path = os.path.join('.', 'HijackLibs')
if not os.path.exists(repo_path):
    subprocess.run(['git', 'clone', repo_url, repo_path], check=True)

with open(csv_file, 'w', newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
    writer.writeheader()

    glob_pattern = os.path.join(repo_path, 'yml', '**', '*.yml').replace(os.sep, '/')
    # Loop through each YAML file recursively in the 'yml' directory
    for filename in glob.glob(glob_pattern, recursive=True):
        with open(filename, 'r') as file:
            data = yaml.safe_load(file)
            relative_path = os.path.relpath(filename, os.path.join(repo_path, 'yml'))
            hijacklib_link = os.path.join('HijackLibs', 'yml', relative_path).replace(os.sep, '/')

            replaced_paths = [replace_variables(loc) for loc in data.get('ExpectedLocations', [])]
            final_paths = [path + ('*' if not path.endswith('*') else '') for path in replaced_paths]

            # Build the row for CSV
            csv_row = {
                'file_name': data.get('Name', ''),
                'expected_file_path': ";".join(final_paths),
                'vulnerable_file_name': replace_variables(data.get('VulnerableExecutables', [])[0].get('Path', '')) if data.get('VulnerableExecutables', []) else '',
                'file_type': data.get('VulnerableExecutables', [])[0].get('Type', '') if data.get('VulnerableExecutables', []) else '',
                'file_hash': ";".join(data.get('VulnerableExecutables', [])[0].get('SHA256', [])) if data.get('VulnerableExecutables', []) else '',
                'link': ";".join(data.get('Resources', [])),
                'hijacklib_link': hijacklib_link
            }

            writer.writerow(csv_row)
