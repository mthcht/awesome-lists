rule Trojan_Win32_Waprox_A_2147652715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Waprox.A"
        threat_id = "2147652715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Waprox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 08 8b 02 6b c0 1f 8b 4d 0c 03 4d fc 0f b6 11 03 c2 8b 4d 08 89 01 eb d5}  //weight: 2, accuracy: High
        $x_1_2 = {70 6f 6c 79 5f 73 6f 63 6b 73 2e 64 6c 6c 00 77 6d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {70 72 6f 78 79 77 68 61 74 78 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_4 = {4d 61 63 68 69 6e 65 47 75 69 64 00 62 6c 6f 77 6a 6f 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Waprox_A_2147656678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Waprox.gen!A"
        threat_id = "2147656678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Waprox"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 0f 68 38 04 00 00 ff 15 ?? ?? ?? ?? 66 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 43 5c 99 f7 f9 80 c2 5a 88 56 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

