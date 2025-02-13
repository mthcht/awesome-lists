rule Trojan_Win64_Thundershell_A_2147723565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Thundershell.A"
        threat_id = "2147723565"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Thundershell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ea 01 83 fa 01 77 05 e8 ?? ?? ?? ?? b8 01 00 00 00 48 83 c4 28 c3}  //weight: 10, accuracy: Low
        $x_10_2 = {41 b8 01 10 00 00 4c 8d 4c 24 20 4c 89 c9 e8 ?? ?? ?? ?? 49 89 c1 8b 05 ?? ?? ?? ?? 85 c0 74 08}  //weight: 10, accuracy: Low
        $x_10_3 = {44 6c 6c 4d 61 69 6e 00 45 78 65 63 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

