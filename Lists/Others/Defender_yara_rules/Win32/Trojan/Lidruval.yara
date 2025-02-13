rule Trojan_Win32_Lidruval_A_2147631727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lidruval.A"
        threat_id = "2147631727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lidruval"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 03 f9 8a 17 32 d0 88 17 2b f9 41 c1 e8 08 e2 ef}  //weight: 1, accuracy: High
        $x_1_2 = {83 f8 23 75 59 8b 4d fc c6 01 23 8b 55 fc 83 c2 01 89 55 fc 8b 45 08 03 45 f8 33 c9 8a 08}  //weight: 1, accuracy: High
        $x_1_3 = {68 30 20 00 00 68 ?? ?? ?? ?? 8d 95 ?? ?? ff ff 52 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

