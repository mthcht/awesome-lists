rule Trojan_Win32_Carfekab_A_2147684978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Carfekab.gen!A"
        threat_id = "2147684978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Carfekab"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 75 1f 6a 00 6a 01 6a 05 8d 45 f4 50 b9 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? b8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {00 5c 63 6f 6e 66 69 67 2e 62 69 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 2f 49 4d 20 66 69 72 65 66 6f 78 2e 65 78 65 20 2f 46 00 00 [0-16] 74 61 73 6b 6b 69 6c 6c 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {34 61 62 64 63 33 38 31 2d 33 39 34 38 2d 34 36 37 32 2d 62 30 38 36 2d 66 63 38 39 62 39 37 62 61 39 63 63 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

