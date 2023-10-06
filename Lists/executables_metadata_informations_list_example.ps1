$results = @()

# Get sigcheck64.exe in the current directory
Get-ChildItem -Path "C:\Windows\System32" -Filter "*.exe" | ForEach-Object {
    $output = & ".\sigcheck64.exe" -a $_.FullName | Out-String
    $output = $output -split "`r`n"

    # Initialize an empty hash table to hold the key-value pairs for the current .exe file
    $hash = @{}

    # Populate the hash table with the key-value pairs from the sigcheck output
    foreach ($line in $output) {
        if ($line -match "(.*):\s*(.*)") {
            $hash[$matches[1].Trim()] = $matches[2].Trim()
        }
    }

    # Create a custom object from the hash table and add it to the results array
    $results += [PSCustomObject]@{
        "Executable Name" = $_.Name
        "Original Name"    = $hash["Original Name"]
        "ProductName"      = $hash["Product"]
        "Internal Name"    = $hash["Internal Name"]
        "Company"          = $hash["Description"]
        "Description"      = $hash["Company"]
        "Publisher"        = $hash["Publisher"]

    }
}

# Export the results array to a CSV file
$results | Export-Csv -Path ".\executables_metadata_informations_list.csv" -NoTypeInformation -Encoding UTF8
