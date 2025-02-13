rule Trojan_Win32_Mesoum_A_2147607589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mesoum.A"
        threat_id = "2147607589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mesoum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b fd 8a 14 01 32 d3 30 10 88 14 01 40 4f 75 f2}  //weight: 2, accuracy: High
        $x_1_2 = {8b 4d f0 c7 81 ?? ?? 00 00 00 34 12 00 8b 55 f0 c7 82 ?? ?? 00 00 00 78 56 00}  //weight: 1, accuracy: Low
        $x_1_3 = {79 08 49 81 c9 00 ff ff ff 41 8a 4c 0c 10 8a 1c 10 32 d9 88 1c 10 40 3b c6 7c dd}  //weight: 1, accuracy: High
        $x_1_4 = "DnsMonitor_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

