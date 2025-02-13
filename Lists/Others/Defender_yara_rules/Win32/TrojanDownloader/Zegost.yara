rule TrojanDownloader_Win32_Zegost_B_2147692234_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zegost.B"
        threat_id = "2147692234"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/1/mubiao.htm" ascii //weight: 1
        $x_1_2 = "20rj." ascii //weight: 1
        $x_1_3 = "C:\\QQ.exe" ascii //weight: 1
        $x_1_4 = "d09f2340818511d396f6aaf844c7e325" ascii //weight: 1
        $x_1_5 = "net user Administrator /fullname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Zegost_C_2147696596_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zegost.C"
        threat_id = "2147696596"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 11 80 c3 ?? 88 1c 11 8b 54 24 04 8a 1c 11 80 f3 ?? 88 1c 11 41 3b ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {50 51 c6 44 24 ?? 4b c6 44 24 ?? 6f c6 44 24 ?? 74 c6 44 24 ?? 68 c6 44 24 ?? 65 c6 44 24 ?? 72 c6 44 24 ?? 35 c6 44 24 ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zegost_H_2147697473_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zegost.H"
        threat_id = "2147697473"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 11 0f be 45 f0 2b d0 8b 4d fc 03 4d f8 88 11 8b 55 fc 03 55 f8 0f be 02 0f be 4d ec 33 c1 8b 55 fc 03 55 f8 88 02 e8 ?? ?? ?? ?? eb a6}  //weight: 1, accuracy: Low
        $x_1_2 = {fe ff ff 4e c6 85 ?? fe ff ff 65 c6 85 ?? fe ff ff 74 c6 85 ?? fe ff ff 53 c6 85 ?? fe ff ff 79 c6 85 ?? fe ff ff 73 c6 85 ?? fe ff ff 74 c6 85 ?? fe ff ff 32 c6 85 ?? fe ff ff 2e c6 85 ?? fe ff ff 64 c6 85 ?? fe ff ff 6c c6 85 ?? fe ff ff 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zegost_D_2147709831_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zegost.D"
        threat_id = "2147709831"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 10 32 d3 02 d3 88 10 40 4e 75 f4}  //weight: 1, accuracy: High
        $x_1_2 = {8b 57 50 8b 47 34 6a 04 68 00 20 00 00 52 50 ff d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zegost_E_2147714367_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zegost.E!bit"
        threat_id = "2147714367"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 10 32 d3 02 d3 88 10 40 4e 75 f4}  //weight: 2, accuracy: High
        $x_2_2 = {8b 54 24 04 8a 1c 11 80 c3 ?? 88 1c 11 8b 54 24 04 8a 1c 11 80 f3 ?? 88 1c 11 41 3b c8 7c e1}  //weight: 2, accuracy: Low
        $x_1_3 = {4b c6 44 24 ?? 52 c6 44 24 ?? 4e c6 44 24 ?? 4c c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zegost_ARA_2147851452_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zegost.ARA!MTB"
        threat_id = "2147851452"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4c 24 08 8a 14 08 80 c2 7a 88 14 08 8b 4c 24 08 8a 14 08 80 f2 59 88 14 08 40 3b c6 7c e1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

