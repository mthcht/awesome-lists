rule Trojan_Win32_Lycutosso_A_2147697273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lycutosso.A"
        threat_id = "2147697273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lycutosso"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 6f 70 79 46 69 6c 65 53 61 66 65 00 63 72 65 61 74 65 5f 64 69 72 5f 6c 69 6e 6b}  //weight: 2, accuracy: High
        $x_2_2 = {64 65 63 72 79 70 74 00 64 69 73 69 6e 66 65 63 74 00 69 6e 66 65 63 74}  //weight: 2, accuracy: High
        $x_1_3 = {b8 ff ff 00 00 66 89 01 46 81 fe 2a 2c 0a 00 7c ?? 83 c1 02 4a 75}  //weight: 1, accuracy: Low
        $x_1_4 = {80 e1 06 0f be c9 f7 d9 1b c9 f7 d1 85 c8 0f 84 ?? 00 00 00 8d 74 24 30 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

