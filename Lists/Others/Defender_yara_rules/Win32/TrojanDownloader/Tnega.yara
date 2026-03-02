rule TrojanDownloader_Win32_Tnega_RR_2147779748_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tnega.RR!MTB"
        threat_id = "2147779748"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 5c 24 10 48 89 74 24 18 48 89 7c 24 20 55 48 8b ec 48 83 ec 70 48 8b 05 3e 4e 00 00 48 33 c4 48 89 45 f0 48 8b d9 48 8b d1 33 f6}  //weight: 1, accuracy: High
        $x_1_2 = "URLDownloadToFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tnega_ARA_2147894581_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tnega.ARA!MTB"
        threat_id = "2147894581"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 44 3d e8 6a 01 8d 4d f0 51 68 ?? ?? ?? ?? 88 45 f0 e8 ?? ?? ?? ?? 88 44 3d e8 47 83 ff 04 7c df}  //weight: 2, accuracy: Low
        $x_2_2 = "aHR0cDovL2R3LjljaWRjLmNuL2J5ZTAwMS5iaW4=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

