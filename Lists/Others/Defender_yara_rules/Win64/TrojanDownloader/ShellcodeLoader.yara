rule TrojanDownloader_Win64_ShellcodeLoader_RP_2147908421_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/ShellcodeLoader.RP!MTB"
        threat_id = "2147908421"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "huorongqnmlb" wide //weight: 1
        $x_1_2 = "huorong" wide //weight: 1
        $x_1_3 = "InternetOpenW" ascii //weight: 1
        $x_1_4 = "InternetOpenUrlW" ascii //weight: 1
        $x_1_5 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_ShellcodeLoader_RP_2147908421_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/ShellcodeLoader.RP!MTB"
        threat_id = "2147908421"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 83 ec 18 c7 04 24 8a 00 00 00 c7 44 24 04 9d 07 00 00 8b 04 24 99 83 e0 01 33 c2 2b c2 8b 0c 24 ff c1 89 0c 24 85 c0 7e 0e}  //weight: 10, accuracy: High
        $x_1_2 = "InternetOpenW" ascii //weight: 1
        $x_1_3 = "InternetOpenUrlW" ascii //weight: 1
        $x_1_4 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

