rule TrojanDownloader_Win32_Smordess_A_2147719201_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Smordess.A"
        threat_id = "2147719201"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Smordess"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c \"PowerShell (New-Object System.Net.WebClient).DownloadFile(" ascii //weight: 1
        $x_1_2 = "(New-Object -com Shell.Application).ShellExecute('mess.exe')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

