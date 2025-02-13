rule Trojan_Win32_Thundershell_A_2147723564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Thundershell.A"
        threat_id = "2147723564"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Thundershell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 5c 24 14 e8 ?? ?? ?? ?? 83 fb 01 74 05 83 fb 02 75 05 e8}  //weight: 10, accuracy: Low
        $x_10_2 = {81 c1 01 10 00 00 89 94 24 1c 10 00 00 [0-8] c1 e9 02 f3 a5 85 d2}  //weight: 10, accuracy: Low
        $x_10_3 = {44 6c 6c 4d 61 69 6e 40 31 32 00 45 78 65 63 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

