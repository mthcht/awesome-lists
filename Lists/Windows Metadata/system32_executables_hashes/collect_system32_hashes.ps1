$system32_executables = @()
$hashes_dict = @{}
$outfile = "$env:windir\Temp\system32_executables_hashes.csv"
Get-ChildItem $env:windir\System32 -Recurse -Filter *.exe -ErrorAction SilentlyContinue -Force| ForEach-Object {$system32_executables += $_.FullName}
if($system32_executables){
    ForEach($exe in $system32_executables){
        Write-Host -ForegroundColor Cyan "[Info] Getting hash for $exe"
        $hash_exe = 'unknown'
        $hash_exe = Get-FileHash -Algorithm SHA256 $exe -Verbose -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Hash
        if($hash_exe -neq 'unknown'){
            Write-Host -ForegroundColor Green "[Success] Hash for $exe is $hash_exe"
            $exe= ($exe -replace "^[a-zA-Z]\:\\",'*').replace("\", "\\*")
            $hashes_dict.Add($exe, $hash_exe)
        }
        else{
            Write-Host -ForegroundColor Red "[Error] Failed to get hash for $exe"
        }
    }
    if($hashes_dict){
        Write-Host -ForegroundColor Cyan "[Info] Renaming headers..."
        $hashes_dict = $hashes_dict.keys | Select-Object @{l='file_path';e={$_}},@{l='file_hash';e={$hashes_dict.$_}}
        Write-Host -ForegroundColor Cyan "[Info] Saving hashes for executables in $env:windir\System32 in $outfile ..."
        $hashes_dict.GetEnumerator() | Select-Object file_path,file_hash | ConvertTo-Csv -NoTypeInformation -Verbose | ForEach-Object {$_.Replace('"','')} | Out-File -FilePath $outfile -Encoding UTF8 -Verbose 
    }
}
