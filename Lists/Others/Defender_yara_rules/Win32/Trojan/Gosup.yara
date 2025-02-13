rule Trojan_Win32_Gosup_A_2147649066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gosup.A"
        threat_id = "2147649066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gosup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2c 72 75 6e 00 25 00 72 75 6e 64 6c 6c 33 32 20 22}  //weight: 1, accuracy: Low
        $x_1_2 = {32 d1 81 e2 ff 00 00 00 8b f2 85 f6 75 08 8b f0 81 e6 ff 00 00 00 8b c7}  //weight: 1, accuracy: High
        $x_1_3 = {6e 6e 65 77 2e 64 6c 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 39 38 37 36 35}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 72 6f 66 69 6c 65 73 2e 69 6e 69 00 00 00 00 00 00 00 00 50 61 74 68 00 00 00 00 50 72 6f 66 69 6c 65 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Gosup_B_2147650714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gosup.B"
        threat_id = "2147650714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gosup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 6e 65 77 2e 64 6c 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 39 38 37 36 35}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 75 f4 8b 07 8a 44 18 ff 8b d0 8b 4d f8 8a 4c 31 ff 32 d1 81 e2 ff 00 00 00 8b f2 85 f6 75 ?? 8b f0 81 e6 ff 00 00 00 8b c7 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

