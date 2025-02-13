rule Trojan_Win32_Atoff_A_2147680425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Atoff.A"
        threat_id = "2147680425"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Atoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 47 6c 6f 62 61 6c 5c 41 74 6f 6d 46 75 6e 00}  //weight: 10, accuracy: High
        $x_1_2 = {51 ff d3 66 85 c0 74 ?? 83 c7 01 81 ff ff ff 00 00 72 e9 8d 94 24 ?? ?? ?? ?? 52 c7 84 24 ?? ?? ?? ?? 94 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {68 ff ff 1f 00 51 89 7c 24 ?? 89 7c 24 ?? c7 44 24 ?? 24 00 00 00 c7 44 24 ?? 03 00 01 00 c7 44 24 ?? 08 00 00 00 89 7c 24 ?? c7 44 24 ?? 04 00 01 00 c7 84 24 ?? 00 00 00 04 00 00 00 89 bc 24 ?? 00 00 00 ff d0 83 c4 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Atoff_B_2147680426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Atoff.B"
        threat_id = "2147680426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Atoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 57 ff 15 ?? ?? ?? ?? 3d 00 68 5b 00 89 44 24 ?? 8b f0 72 05 be 00 68 5b 00 a1 ?? ?? ?? ?? 85 c0 89 74 24 ?? 75 ?? 50 68 00 00 20 03}  //weight: 1, accuracy: Low
        $x_1_2 = {2b cf 83 f9 75 76 05 b9 75 00 00 00 89 4d ?? 8b 55 0c 03 d7 8b c6 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

