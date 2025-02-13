rule TrojanDownloader_Win32_Yektel_H_116917_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Yektel.H"
        threat_id = "116917"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Yektel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "wscmp.dll" ascii //weight: 10
        $x_1_3 = "\\Windows NT\\CurrentVersion\\Windows\\run" ascii //weight: 1
        $x_1_4 = "\\Windows\\CurrentVersion\\Controls Folder\\PIDwmp" ascii //weight: 1
        $x_1_5 = "Bot count =" ascii //weight: 1
        $x_1_6 = "Downloading toolbar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Yektel_A_124145_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Yektel.A"
        threat_id = "124145"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Yektel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 66 81 ff 28 23 7d 52 33 c0 89 04 24 54 6a 00 55 e8 ?? ?? ff ff e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {66 3d 19 04 74 06 66 3d 22 04 75 ?? a1 ?? ?? ?? ?? 8b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Yektel_B_124368_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Yektel.B"
        threat_id = "124368"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Yektel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 66 81 ff 28 23 7d 52 33 c0 89 04 24 54 6a 00 55 e8 ?? ?? ?? ff e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {66 ff 45 ee 66 81 7d ee 28 23 7d 69 33 c0 89 45 f4 8d 45 f4 50 6a 00 8b 45 f8 50 e8 ?? ?? ff ff e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_2_3 = {19 04 74 0b 66 81 3d ?? ?? ?? ?? 22 04 75 1f a1 ?? ?? ?? ?? 8b 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

