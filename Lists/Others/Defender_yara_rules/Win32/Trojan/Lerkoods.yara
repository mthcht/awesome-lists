rule Trojan_Win32_Lerkoods_A_2147653118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lerkoods.A"
        threat_id = "2147653118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lerkoods"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 43 04 c6 43 08 b8 8b 45 08 89 43 09 66 c7 43 0d ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {80 78 18 00 74 14 54 6a 08 8d 50 08 52 8b 50 1c 52 8b 40 04 50 e8}  //weight: 1, accuracy: High
        $x_1_3 = {4b 65 72 6e 65 6c 33 32 62 69 74 73 2e 64 6c 6c 00 45 6e 64 48 6f 6f 6b 73 00 53 74 61 72 74 48 6f 6f 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

