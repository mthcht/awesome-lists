rule Trojan_Win32_Gaboc_A_2147622031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gaboc.A"
        threat_id = "2147622031"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gaboc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 58 66 89 7d ea 66 89 45 e8 66 89 45 e6 66 89 45 e4 66 89 45 e2 66 89 45 de 8d 45 dc 50 66 c7 45 dc c6 07 ff d6 bf 10 27 00 00 57 ff 15 ?? ?? ?? ?? 83 7d f8 00 75 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 1c 5e a1 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 34 06 e8 ?? ?? ?? ?? 59 85 c0 59 74 61 83 c6 04 81 fe 94 00 00 00 7c dd}  //weight: 1, accuracy: Low
        $x_1_3 = {74 25 57 6a 05 56 ff 15 ?? ?? ?? ?? 6a ff 8b f8 ff 74 24 10 e8 ?? ?? ?? ?? 59 50 6a 00 ff d7}  //weight: 1, accuracy: Low
        $x_1_4 = {25 73 25 73 26 6d 61 63 68 69 6e 65 6e 61 6d 65 3d 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

