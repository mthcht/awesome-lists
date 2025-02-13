rule TrojanDownloader_Win32_Kanav_B_2147680331_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kanav.B"
        threat_id = "2147680331"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kanav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 59 33 c0 8d bd ?? ?? ff ff f3 ab 66 ab aa 8d 85 ?? ?? ff ff 50 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = "81A6A8D20CA2AE" ascii //weight: 1
        $x_1_3 = {2d 73 74 61 72 74 00 73 74 61 72 74}  //weight: 1, accuracy: High
        $x_1_4 = "\\AYLaunch.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Kanav_H_2147680332_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kanav.H"
        threat_id = "2147680332"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kanav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c0 e1 04 02 0c bd ?? ?? ?? ?? 32 4d ?? 43 46 88 08 (e8|ff 15) ?? ?? ?? ?? 3b f0 [0-1] 7c 9b}  //weight: 2, accuracy: Low
        $x_2_2 = {83 ff 31 7e 05 83 ef 32 eb 03 83 c7 0a 8d 45 f0 50 ff d6 0f b7 45 fc 3b c7 75}  //weight: 2, accuracy: High
        $x_1_3 = "reg delete \"HKEY_CURRENT_USER\\Software\\Microsoft\\Active Setup\\Installed Components\\" ascii //weight: 1
        $x_1_4 = {5c 42 61 74 74 6c 65 2e 6e 65 74 5c 49 64 65 6e 74 69 74 79 [0-64] 2d 73 74 61 72 74}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 56 33 4d 65 64 69 63 2e 65 78 65 [0-5] 56 65 72 73 69 6f 6e 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 6c 65}  //weight: 1, accuracy: Low
        $x_1_6 = {56 33 4d 65 64 69 63 2e 65 78 65 00 00 25 73 5c 41 59 4c 61 75 6e 63 68 2e 65 78 65 00 25 73 5c 75 73 70 31 30 2e 64 6c 6c 2e 62 61 6b}  //weight: 1, accuracy: High
        $x_1_7 = "<description><![CDATA[" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Kanav_CH_2147746192_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kanav.CH!MTB"
        threat_id = "2147746192"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kanav"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InternetReadFile" ascii //weight: 1
        $x_1_2 = "%SystemRoot%\\system32\\GoogleUpdate.exe" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Blizzard Entertainment\\Battle.net" ascii //weight: 1
        $x_1_4 = "reg delete \"HKEY_CURRENT_USER\\Software\\Microsoft\\Active Setup\\Installed Components" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

