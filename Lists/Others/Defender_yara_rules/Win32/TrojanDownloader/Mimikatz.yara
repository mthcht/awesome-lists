rule TrojanDownloader_Win32_Mimikatz_A_2147836959_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mimikatz.A!MTB"
        threat_id = "2147836959"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_2 = "cmd /c C:\\Users\\Public\\Documents\\" ascii //weight: 1
        $x_1_3 = "cmd.exe /c taskkill /f /t /im" ascii //weight: 1
        $x_1_4 = "PromptOnSecureDesktop" ascii //weight: 1
        $x_1_5 = "EnableLUA" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii //weight: 1
        $x_1_7 = "://department.microsoftmiddlename.tk/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Mimikatz_RDA_2147838558_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mimikatz.RDA!MTB"
        threat_id = "2147838558"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//department.microsoftmiddlename.tk/picturess/" ascii //weight: 1
        $x_1_2 = "RDSv1.dll" ascii //weight: 1
        $x_1_3 = "CEECDoc" ascii //weight: 1
        $x_1_4 = "CEECView" ascii //weight: 1
        $x_1_5 = "C:/Users/Public/Documents/RDSv1.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

