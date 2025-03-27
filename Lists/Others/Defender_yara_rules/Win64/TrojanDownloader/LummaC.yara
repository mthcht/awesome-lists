rule TrojanDownloader_Win64_LummaC_CCJR_2147937097_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/LummaC.CCJR!MTB"
        threat_id = "2147937097"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell -Command \"Add-MpPreference -ExclusionPath" wide //weight: 1
        $x_1_2 = "powershell -Command \"Invoke-WebRequest -Uri" wide //weight: 1
        $x_5_3 = "https://github.com/ricocajpg/farmac/raw/refs/heads/main/" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

