rule TrojanDownloader_Win64_Sdum_GVB_2147958886_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Sdum.GVB!MTB"
        threat_id = "2147958886"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Sdum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -Command" wide //weight: 1
        $x_1_2 = "Add-MpPreference -ExclusionPath" wide //weight: 1
        $x_5_3 = "://softwaretech.pro" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

