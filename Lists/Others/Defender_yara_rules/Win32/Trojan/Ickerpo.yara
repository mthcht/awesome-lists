rule Trojan_Win32_Ickerpo_A_2147633488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ickerpo.A"
        threat_id = "2147633488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ickerpo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f3 a6 0f 94 c0 83 c0 03 8b f8 8b 44 bb fc 80 38 23 74 24 8b 03 6a 21 50 e8 ?? ?? ?? ?? c6 00 00 8b 03 40 6a 7f 50 8d 85 7c ff ff ff}  //weight: 5, accuracy: Low
        $x_5_2 = {8a 08 3a 0a 75 18 84 c9 74 10 8a 48 01 3a 4a 01 75 0c 03 c3 03 d3 84 c9 75 e6 33 c0 eb 05 1b c0 83 d8 ff 85 c0 74 0d}  //weight: 5, accuracy: High
        $x_1_3 = {70 69 6e 67 20 31 2e 31 2e 31 2e 31 20 2d 77 20 35 30 30 30 20 3e 6e 75 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {23 78 63 6f 64 00}  //weight: 1, accuracy: High
        $x_1_5 = "RazorMint" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

