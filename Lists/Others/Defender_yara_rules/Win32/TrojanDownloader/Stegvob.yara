rule TrojanDownloader_Win32_Stegvob_A_2147804018_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Stegvob.gen!A"
        threat_id = "2147804018"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Stegvob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {42 48 75 f2 04 00 80 34 11}  //weight: 2, accuracy: Low
        $x_2_2 = {83 f8 20 7e 32 6a 01 8d 45 ?? b9}  //weight: 2, accuracy: Low
        $x_1_3 = {83 ea 57 03 c2 89 c3 ff d3}  //weight: 1, accuracy: High
        $x_1_4 = "&ok=1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Stegvob_C_2147804205_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Stegvob.C"
        threat_id = "2147804205"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Stegvob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff ff 0f b7 9d ?? ?? ff ff 0f af cb 0f b7 85 ?? ?? ff ff 0f af c8 0f b7 95 ?? ?? ff ff 0f af ca 66 31 4d ba ff 4d ec}  //weight: 5, accuracy: Low
        $x_1_2 = {83 7d bc 01 75 ?? c7 45 bc 02 00 00 00 83 6d c8 06}  //weight: 1, accuracy: Low
        $x_1_3 = {83 7d bc 03 75 ?? c7 45 bc 04 00 00 00 83 6d c8 06}  //weight: 1, accuracy: Low
        $x_1_4 = {83 7d bc 05 75 ?? c7 45 bc 06 00 00 00 83 6d c8 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Stegvob_D_2147804206_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Stegvob.D"
        threat_id = "2147804206"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Stegvob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 bc 66 8b 94 45 9c db ff ff 66 31 55 b6 83 7d bc 05 75}  //weight: 1, accuracy: High
        $x_1_2 = {83 7d c4 06 7d ?? 8b 45 c4 66 8b 55 b6 66 89 94 45 9c db ff ff ff 45 c4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Stegvob_E_2147804209_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Stegvob.E"
        threat_id = "2147804209"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Stegvob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d fc 83 c3 fa 3b fb 77 11 8b c6 3a 43 01 75 03 ff 53 02 83 eb 06 3b fb}  //weight: 1, accuracy: High
        $x_1_2 = ".ru/get.php?search=" wide //weight: 1
        $x_1_3 = {25 00 63 00 25 00 73 00 [0-3] 3a 00 5c 00 50 00 68 00 6f 00 74 00 6f 00 2e 00 73 00 63 00 72 00}  //weight: 1, accuracy: Low
        $x_1_4 = "ieload.net/load.gif?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

