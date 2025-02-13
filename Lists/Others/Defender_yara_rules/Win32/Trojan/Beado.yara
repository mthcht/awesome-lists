rule Trojan_Win32_Beado_A_2147681417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Beado.A"
        threat_id = "2147681417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Beado"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 45 00 73 00 63 00 72 00 69 00 74 00 6f 00 72 00 69 00 6f 00 5c 00 ?? ?? ?? ?? 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 69 00 6f 00 73 00 20 00 64 00 65 00 20 00 53 00 69 00 73 00 74 00 65 00 6d 00 61 00 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {53 00 6f 00 6e 00 72 00 69 00 65 00 20 00 6d 00 69 00 65 00 72 00 64 00 61 00 20 00 3a 00 29 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {63 00 6f 00 75 00 6e 00 74 00 72 00 79 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {67 00 70 00 6a 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {3c 00 21 00 2d 00 2d 00 ?? ?? ?? ?? ?? ?? ?? ?? 69 00 69 00 69 00 69 00 69 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

