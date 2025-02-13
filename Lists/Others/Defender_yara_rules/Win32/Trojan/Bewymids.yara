rule Trojan_Win32_Bewymids_A_2147640367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bewymids.A"
        threat_id = "2147640367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bewymids"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 18 6a 02 6a 98 57 e8 ?? ?? ?? ?? 83 c4 0c 85 c0 74 0b}  //weight: 1, accuracy: Low
        $x_1_2 = {80 3b 63 8b f8 0f 85 ?? ?? 00 00 80 7b 01 64 0f 85 ?? ?? 00 00 80 7b 02 20 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 14 08 02 d0 80 c2 5a 32 d0 88 14 08 40 3b 44 24 08 7c ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

