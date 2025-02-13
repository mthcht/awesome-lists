rule Trojan_Win32_Tacpud_A_2147708734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tacpud.A"
        threat_id = "2147708734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tacpud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 69 73 61 62 6c 65 5f 41 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 00 52 00 43 00 6f 00 6e 00 5d 00 7c 00 [0-16] 5b 00 4e 00 65 00 77 00 5d 00 7c 00 [0-16] 5b 00 52 00 63 00 6f 00 6e 00 5d 00 7c 00 [0-16] 5b 00 44 00 6f 00 6e 00 65 00 5d 00 7c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5b 00 4d 00 6f 00 76 00 65 00 5d 00 7c 00 [0-16] 41 00 43 00 54 00 [0-16] 5b 00 54 00 43 00 50 00 5d 00 7c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5b 00 55 00 44 00 50 00 5d 00 7c 00 [0-32] 5b 00 48 00 54 00 54 00 5d 00 7c 00 [0-16] 38 00 30 00}  //weight: 1, accuracy: Low
        $x_1_5 = {53 00 54 00 4f 00 50 00 [0-16] 5b 00 57 00 61 00 69 00 74 00 5d 00 7c 00 [0-16] 45 00 58 00 49 00 54 00}  //weight: 1, accuracy: Low
        $x_1_6 = {5b 00 52 00 5d 00 7c 00 [0-16] 5b 00 4e 00 5d 00 7c 00 [0-16] 5b 00 44 00 [0-32] 4f 00 70 00 65 00 6e 00 [0-16] 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

