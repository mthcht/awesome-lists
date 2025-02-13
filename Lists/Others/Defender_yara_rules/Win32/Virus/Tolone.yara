rule Virus_Win32_Tolone_A_2147601514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Tolone.gen!A"
        threat_id = "2147601514"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Tolone"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 59 53 5f 4d 55 54 45 58 00}  //weight: 1, accuracy: High
        $x_1_2 = {6a 58 68 4d 55 54 45 68 53 59 53 5f [0-80] 6a 58 68 4d 55 54 45 68 53 59 53 5f}  //weight: 1, accuracy: Low
        $x_1_3 = {f3 a4 6a 58 68 4d 55 54 45 68 53 59 53 5f [0-15] 50 68 43 3a 5c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {81 7f fc 53 43 52 00 [0-15] 81 7f fc 73 63 72 00}  //weight: 1, accuracy: Low
        $x_1_5 = {81 7f fc 45 58 45 00 [0-15] 81 7f fc 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_6 = {50 54 50 55 e8 05 00 00 00 e9 ?? ?? ?? ?? 50 50 e8 ?? ?? ?? ?? 50 68 88 4a 88 d9 e8 ?? ?? ?? ?? ff d0 0b c0 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

