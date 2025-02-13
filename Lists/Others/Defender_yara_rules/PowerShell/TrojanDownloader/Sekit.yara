rule TrojanDownloader_PowerShell_Sekit_C_2147741073_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Sekit.C"
        threat_id = "2147741073"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Sekit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\powershell.exe" wide //weight: 1
        $x_1_2 = "iex($env:" wide //weight: 1
        $x_1_3 = "=$env:temp+'\\" wide //weight: 1
        $x_1_4 = ".DownloadFile('http" wide //weight: 1
        $x_1_5 = "Invoke-Item $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

