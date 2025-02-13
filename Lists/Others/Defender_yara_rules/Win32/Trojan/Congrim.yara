rule Trojan_Win32_Congrim_A_2147657182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Congrim.gen!A"
        threat_id = "2147657182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Congrim"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 38 3a cb 75 0a c6 84 14 ?? ?? ?? ?? 2c eb 07}  //weight: 1, accuracy: Low
        $x_1_2 = {50 75 74 46 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 74 24 3c 56 ff d3 83 c4 28 85 c0 5f 5d 74 14}  //weight: 1, accuracy: High
        $x_1_4 = {8a 5e 01 0a 59 01 8a 48 01 40 0a cb 42 81 ff 00 01 00 00 88 08 0f 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

