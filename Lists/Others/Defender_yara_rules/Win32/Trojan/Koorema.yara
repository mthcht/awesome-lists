rule Trojan_Win32_Koorema_A_2147634448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koorema.A"
        threat_id = "2147634448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koorema"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 c6 02 e9 89 42 01 8d 7a 05 7e 13 8b d1 c1 e9 02 b8 cc cc cc cc f3 ab 8b ca 83 e1 03 f3 aa}  //weight: 1, accuracy: High
        $x_1_2 = {c7 06 45 34 52 74 ff 15 ?? ?? ?? ?? 8d 46 14 50 c7 00 9c 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {72 75 6e 64 6c 6c 33 32 20 22 25 73 22 2c 58 46 52 65 73 74 61 72 74 00 5c 69 6e 65 74 73 72 76 5c 77 61 6d 72 65 67 2e 64 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

