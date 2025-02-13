rule Trojan_Win32_Servlice_A_2147681145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Servlice.A"
        threat_id = "2147681145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Servlice"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {57 69 6e 64 6f 77 73 20 4d 65 73 73 61 67 65 20 53 65 72 76 6c 63 65 00}  //weight: 2, accuracy: High
        $x_1_2 = {33 c0 8a 88 ?? ?? ?? ?? 30 0c 37 40 83 f8 07 72 f1 83 3d ?? ?? ?? ?? 00 74 03 f6 14 37}  //weight: 1, accuracy: Low
        $x_1_3 = {78 30 72 62 30 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 31 2e 65 78 65 20 31 20 45 4e 41 42 4c 45 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

