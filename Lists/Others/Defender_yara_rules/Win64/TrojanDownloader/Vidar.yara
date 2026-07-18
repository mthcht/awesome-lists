rule TrojanDownloader_Win64_Vidar_A_2147827732_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Vidar.A!MTB"
        threat_id = "2147827732"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "create_directory" ascii //weight: 1
        $x_1_2 = "remove_all" ascii //weight: 1
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = "runas" wide //weight: 1
        $x_1_5 = "sleep" wide //weight: 1
        $x_1_6 = "rm -Force %s" wide //weight: 1
        $x_1_7 = "Add-MpPreference -ExclusionPath 'C:\\ProgramData'" wide //weight: 1
        $x_1_8 = "Add-MpPreference -ExclusionPath 'C:\\Users\\Public'" wide //weight: 1
        $x_1_9 = "Add-MpPreference -ExclusionPath 'C:\\'" wide //weight: 1
        $x_1_10 = "schtas" wide //weight: 1
        $x_1_11 = "/creat" wide //weight: 1
        $x_1_12 = "ONLOGON /T" wide //weight: 1
        $x_1_13 = "/RL HIGH" wide //weight: 1
        $x_1_14 = "C:\\Windows\\System32\\djoin.exe" ascii //weight: 1
        $x_1_15 = "URLDownloadToFileW" ascii //weight: 1
        $x_1_16 = "ShellExecuteW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Vidar_AH_2147973730_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Vidar.AH!MTB"
        threat_id = "2147973730"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {41 0f b6 c1 42 32 04 1a 88 04 0a ff c2 0f b6 84 24 87 00 00 00 34 ?? 88 04 24 0f b6 84 24 40 01 00 00 fe c0 88 84 24 40 01 00 00 0f b6 04 24 fe c0 88 04 24 41 3b d0 75}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

