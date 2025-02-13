rule Trojan_Win32_Enturp_A_2147650945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Enturp.A"
        threat_id = "2147650945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Enturp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a c1 c0 e8 04 c0 e1 04 0a c1 88 02 8a 4c 16 01 42 84 c9 75 eb}  //weight: 2, accuracy: High
        $x_2_2 = {8b f0 56 6a 01 6a 74 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 1c 8b 5c 24 20}  //weight: 2, accuracy: Low
        $x_1_3 = {5b 45 4e 54 5d 0d 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

