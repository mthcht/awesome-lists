# Get the list of Github URL from the file
# example usage : powershell -ExecutionPolicy Bypass -File '.\get_forked_projects_list.ps1' -FilePath .\offensive_tools_list.csv

[CmdletBinding()]
param (
  [string]$FilePath
)

$RepoUrls = Get-Content -Path $FilePath

#Authenticate to Github
$GitHubToken = 'FIXME_GITHUB_API_Token'
$headers = @{Authorization = "token $GitHubToken"}

# Get the list of all the forked projects from the repository 
$PageNumber = 1 


# Set the rate limit for the GitHub API
$RateLimit = Invoke-RestMethod -Uri "https://api.github.com/rate_limit" -Headers $headers
 
# Get the remaining requests for the period 
$RemainingRequests = $RateLimit.rate.remaining 
 
foreach ($RepoUrl in $RepoUrls) 
{ 
    # Get the name of the repository from the URL 
    $RepoName = $RepoUrl -replace 'https://github.com/', '' 
    # Create an empty array to store the list of forked projects 
    $ForkedReposList = @() 
    # Get the list of forked projects from the repository with pagination 
    $ForkedRepos = Invoke-WebRequest -Uri "https://api.github.com/repos/$RepoName/forks?page=$PageNumber" -Headers $headers | ConvertFrom-Json 
  
    # Loop through the pages until the last page 
    while ($ForkedRepos.Length -ne 0) 
    { 
        # Iterate through each forked repository 
        foreach ($ForkedRepo in $ForkedRepos) 
        { 
            # Store the URL of the repository in the array 
            $ForkedReposList += $ForkedRepo.html_url 
        } 
  
        # Increment the page number 
        $PageNumber++ 
        # Get the list of forked projects from the repository with pagination 
        $ForkedRepos = Invoke-WebRequest -Uri "https://api.github.com/repos/$RepoName/forks?page=$PageNumber" -Headers $headers | 
                       ConvertFrom-Json 
        # Decrement the number of remaining requests 
        $RemainingRequests-- 
        # If the rate limit has been exceeded, break out of the loop 
        if ($RemainingRequests -le 100) 
        { 
            break 
        } 
    }
    $repo = $RepoName.Split('/')[1]
    # Save the list of forked projects to file 
    $ForkedReposList | Out-File -FilePath "$PSScriptRoot\$repo-forks.txt"
    $RepoUrl | Out-File -FilePath "$PSScriptRoot\$repo-forks.txt" -Append
}
