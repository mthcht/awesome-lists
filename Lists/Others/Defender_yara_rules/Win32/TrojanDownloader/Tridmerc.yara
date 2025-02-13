rule TrojanDownloader_Win32_Tridmerc_A_2147607401_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tridmerc.gen!A"
        threat_id = "2147607401"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tridmerc"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 04 01 00 00 6a 40 e8 54 00 00 00 8b d8 50 68 04 01 00 00 e8 41 00 00 00 6a 0b 59 8b fb 03 f8 be ?? 03 40 00 f3 a4 51 51 53 68 ?? 03 40 00 51 e8 3d 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {51 53 e8 25 00 00 00 53 e8 19 00 00 00 50 e8 01 00 00 00 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tridmerc_B_2147607402_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tridmerc.gen!B"
        threat_id = "2147607402"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tridmerc"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e6 02 b8 65 89 07 6c}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e6 07 81 e6 80 56 2c 9d 31 f7 89 fe c1 e6 0f 81 e6 00 00 c6 ef}  //weight: 1, accuracy: High
        $x_1_3 = {75 2c 6a 00 8d 85 d8 fd ff ff 50 e8 ?? ?? 00 00 83 f8 1f 76 00 8d 85 d8 fd ff ff 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

