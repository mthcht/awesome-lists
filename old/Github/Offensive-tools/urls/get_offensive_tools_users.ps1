
#Create an array to store the github URLs
$githubUrls = @()

#Get the path to the CSV file
$csvPath = $Args[0]

#Read the content of the CSV file
$csvContent = Get-Content $csvPath

#Loop through the CSV file content
foreach ($line in $csvContent) {
  #Add the argument to the array
  $githubUrls += $line
}

#Create an array to store the usernames
$usernames = @()


#Loop through the URLs
foreach ($url in $githubUrls) {
  #Split the URL to get the username
  $urlParts = $url.Split('/')[3]
  #Add the username to the username array
  $usernames += $urlParts
}

#Create the output file
$outputFile = "$PSScriptRoot\offensive-github-users.csv"

#Create the output file and add the usernames to it
$usernames | Out-File -FilePath $outputFile