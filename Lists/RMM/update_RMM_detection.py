import csv
import requests
import pandas as pd
import os
import io

# URLs of the additional CSV files
additional_files = {
    "suspicious_windows_services_names_list": "https://github.com/mthcht/awesome-lists/raw/main/Lists/suspicious_windows_services_names_list.csv",
    "suspicious_windows_firewall_rules_list": "https://github.com/mthcht/awesome-lists/raw/main/Lists/suspicious_windows_firewall_rules_list.csv",
    "suspicious_windows_tasks_list": "https://github.com/mthcht/awesome-lists/raw/main/Lists/suspicious_windows_tasks_list.csv",
    "suspicious_ports_list": "https://github.com/mthcht/awesome-lists/raw/main/Lists/suspicious_ports_list.csv",
    "suspicious_named_pipe_list": "https://github.com/mthcht/awesome-lists/raw/main/Lists/suspicious_named_pipe_list.csv",
    "suspicious_http_user_agents_list": "https://github.com/mthcht/awesome-lists/raw/main/Lists/suspicious_http_user_agents_list.csv"
}

# Function to download and read a CSV file into a DataFrame
def download_csv_to_df(url):
    response = requests.get(url)
    response.raise_for_status()
    df = pd.read_csv(io.StringIO(response.text))
    return df

# Download the threathunting-keywords CSV file
url = 'https://github.com/mthcht/ThreatHunting-Keywords/raw/main/threathunting-keywords.csv'
output_file = 'RMM_detection_patterns_list.csv'
response = requests.get(url)
response.raise_for_status()

# Process the threathunting-keywords CSV content
filtered_rows = []
first_row = True

for line in response.iter_lines(decode_unicode=True):
    if first_row:
        header = next(csv.reader([line]))
        first_row = False
    else:
        row = next(csv.reader([line]))
        if row[header.index('metadata_category')] == 'RMM':
            filtered_rows.append(row)

# Create a DataFrame from the filtered rows
df = pd.DataFrame(filtered_rows, columns=header)

# Debug: Check for 'anydesk' entries
# print("AnyDesk entries in threathunting-keywords.csv:")
# print(df[df['metadata_tool'].str.contains('anydesk', case=False)])

# Sort the DataFrame by 'metadata_tool' column
df_sorted = df.sort_values(by='metadata_tool', ascending=True)

# Write the sorted DataFrame to the output CSV file
df_sorted.to_csv(output_file, index=False)

# Create separate directories and CSV files for each unique value in 'metadata_tool'
unique_tools = df_sorted['metadata_tool'].unique()

for tool in unique_tools:
    # Create a directory for the tool
    os.makedirs(tool, exist_ok=True)
    
    # Create a DataFrame for the tool
    tool_df = df_sorted[df_sorted['metadata_tool'] == tool]
    
    # Save the DataFrame to a CSV file inside the tool's directory
    tool_df.to_csv(os.path.join(tool, f"{tool}.csv"), index=False)

    # Determine search terms
    search_terms = [tool]
    if tool == "Google Remote Desktop":
        search_terms.append("Chrome Remote Desktop")
    if tool == "Ammyy Admin":
        search_terms.append("AmmyyAdmin")
    if tool == "Kaseya VSA":
        search_terms.append("Kaseya")
    # Search for the tool name and additional terms in the additional files and save relevant lines
    for file_name, file_url in additional_files.items():
        additional_df = download_csv_to_df(file_url)
        
        # Check for matches for each search term
        matched_rows = additional_df[additional_df.apply(lambda row: any(term in ' '.join(row.astype(str)) for term in search_terms), axis=1)]
        
        if not matched_rows.empty:
            clean_file_name = file_name.replace("suspicious_", "")
            matched_file_path = os.path.join(tool, f"{tool}_{clean_file_name}.csv")
            matched_rows.to_csv(matched_file_path, index=False)