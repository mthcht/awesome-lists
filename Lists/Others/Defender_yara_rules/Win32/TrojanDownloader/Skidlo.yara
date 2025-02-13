rule TrojanDownloader_Win32_Skidlo_A_2147650501_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Skidlo.A"
        threat_id = "2147650501"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Skidlo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 c2 03 32 17 47 80 3f 00 75 f5}  //weight: 1, accuracy: High
        $x_1_2 = {ff ff 02 00 01 00 04 00 c7 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Skidlo_B_2147654726_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Skidlo.B"
        threat_id = "2147654726"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Skidlo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "bot_id\":\"%s\",\"version\":" ascii //weight: 1
        $x_1_2 = {69 6e 64 65 78 2e 70 68 70 3f 72 3d 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {66 ad 84 c0 74 11 3c 41 72 06 3c 5a 77 02 0c 20 c1 c2 03 32 d0 eb e9}  //weight: 1, accuracy: High
        $x_1_4 = {e8 00 00 00 00 5d 81 ed ?? ?? ?? ?? bb c0 e6 0a b3 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Skidlo_D_2147708610_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Skidlo.D"
        threat_id = "2147708610"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Skidlo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 c2 03 32 d0 eb ea 8b 75 08 ad 3b c2 75 03 43 eb 1e}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e9 02 f3 a5 0f b7 53 06 8d 83 f8 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {ac 32 c2 42 aa e2 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

